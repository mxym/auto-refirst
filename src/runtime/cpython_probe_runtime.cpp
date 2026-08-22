#include "prts/cpython_probe.hpp"
#include "prts/cpython.hpp"
#include "prts/mapped_file.hpp"
#include "prts/pe.hpp"
#include "prts/pyinstaller.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#endif
namespace prts { namespace {
#include "../reference/cpython_probe_corpus.inc"
#ifdef _WIN32
int hexv(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
std::string lower_ascii(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});return s;}
std::string basename_ascii(const std::string&s){auto p=s.find_last_of("/\\");return p==std::string::npos?s:s.substr(p+1);}
bool parse_probe_output(const std::filesystem::path&p,std::vector<CPythonCompilerProbeCode>&codes,std::string&runtime_version,std::string&error){
    std::ifstream f(p,std::ios::binary);if(!f){error="compiler-probe child did not produce an output file";return false;}std::string line;bool ok=false;
    while(std::getline(f,line)){if(!line.empty()&&line.back()=='\r')line.pop_back();if(line.rfind("ERROR\t",0)==0){error=line.substr(6);return false;}if(line.rfind("OK\t",0)==0){runtime_version=line.substr(3);ok=true;continue;}if(line.rfind("CODE\t",0)!=0)continue;auto a=line.find('\t',5);if(a==std::string::npos){error="malformed compiler-probe CODE record";return false;}CPythonCompilerProbeCode c;c.path=line.substr(5,a-5);auto hx=line.substr(a+1);if(hx.size()%2){error="odd-length compiler-probe hex record";return false;}c.code.reserve(hx.size()/2);for(std::size_t i=0;i<hx.size();i+=2){auto h=hexv(hx[i]),l=hexv(hx[i+1]);if(h<0||l<0){error="invalid compiler-probe hex record";return false;}c.code.push_back(static_cast<std::uint8_t>((h<<4)|l));}codes.push_back(std::move(c));}
    if(!ok){error="compiler-probe child output lacks OK record";return false;}if(codes.empty()){error="compiler-probe child returned no code objects";return false;}return true;
}
bool write_bytes(const std::filesystem::path&p,std::span<const std::uint8_t>d){std::error_code ec;std::filesystem::create_directories(p.parent_path(),ec);std::ofstream o(p,std::ios::binary|std::ios::trunc);if(!o)return false;o.write(reinterpret_cast<const char*>(d.data()),static_cast<std::streamsize>(d.size()));return bool(o);}
#endif
}
#ifdef _WIN32
namespace {
std::wstring quote_arg(const std::wstring&s){std::wstring o=L"\"";std::size_t bs=0;for(wchar_t c:s){if(c==L'\\'){++bs;continue;}if(c==L'\"'){o.append(bs*2+1,L'\\');o.push_back(L'\"');bs=0;continue;}o.append(bs,L'\\');bs=0;o.push_back(c);}o.append(bs*2,L'\\');o.push_back(L'\"');return o;}
std::filesystem::path make_temp_dir(){wchar_t b[32768]{};DWORD n=GetTempPathW(static_cast<DWORD>(std::size(b)),b);if(!n||n>=std::size(b))return{};for(unsigned i=0;i<100;i++){auto p=std::filesystem::path(b)/(L"auto-refirst-pyprobe-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(i));std::error_code ec;if(std::filesystem::create_directory(p,ec))return p;}return{};}
struct TempDir {std::filesystem::path path;~TempDir(){if(!path.empty()){std::error_code ec;std::filesystem::remove_all(path,ec);}}};
std::wstring self_path(){std::wstring b(32768,L'\0');DWORD n=GetModuleFileNameW(nullptr,b.data(),static_cast<DWORD>(b.size()));if(!n||n>=b.size())return{};b.resize(n);return b;}
bool run_child(const std::filesystem::path&dll,const std::filesystem::path&stdlib,const std::filesystem::path&out,std::uint32_t timeout_ms,DWORD&exit_code,std::string&error){
    auto self=self_path();if(self.empty()){error="GetModuleFileNameW failed";return false;}
    std::wstring cmd=quote_arg(self)+L" --internal-cpython-probe "+quote_arg(dll.wstring())+L" "+quote_arg(stdlib.wstring())+L" "+quote_arg(out.wstring());std::vector<wchar_t>buf(cmd.begin(),cmd.end());buf.push_back(0);
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE nul=CreateFileW(L"NUL",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,0,nullptr);if(nul==INVALID_HANDLE_VALUE){error="cannot open NUL for compiler-probe child";return false;}
    STARTUPINFOW si{};si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdInput=nul;si.hStdOutput=nul;si.hStdError=nul;PROCESS_INFORMATION pi{};
    HANDLE job=CreateJobObjectW(nullptr,nullptr);if(job){JOBOBJECT_EXTENDED_LIMIT_INFORMATION ji{};ji.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;SetInformationJobObject(job,JobObjectExtendedLimitInformation,&ji,sizeof(ji));}
    BOOL ok=CreateProcessW(self.c_str(),buf.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT,nullptr,dll.parent_path().empty()?nullptr:dll.parent_path().c_str(),&si,&pi);CloseHandle(nul);if(!ok){if(job)CloseHandle(job);error="compiler-probe CreateProcessW failed: "+std::to_string(GetLastError());return false;}if(job)AssignProcessToJobObject(job,pi.hProcess);CloseHandle(pi.hThread);
    DWORD wr=WaitForSingleObject(pi.hProcess,std::max<std::uint32_t>(timeout_ms,1000u));if(wr==WAIT_TIMEOUT){if(job)TerminateJobObject(job,0x50595054);else TerminateProcess(pi.hProcess,0x50595054);WaitForSingleObject(pi.hProcess,1000);CloseHandle(pi.hProcess);if(job)CloseHandle(job);error="compiler-probe child timed out";return false;}if(wr!=WAIT_OBJECT_0){CloseHandle(pi.hProcess);if(job)CloseHandle(job);error="compiler-probe child wait failed";return false;}GetExitCodeProcess(pi.hProcess,&exit_code);CloseHandle(pi.hProcess);if(job)CloseHandle(job);return true;
}
template<class T>T proc(HMODULE h,const char*n){return reinterpret_cast<T>(GetProcAddress(h,n));}
using PyObject=void;using Py_ssize_t=std::intptr_t;
struct ChildApi {
    void(*Py_SetPath)(const wchar_t*)=nullptr;void(*Py_Initialize)()=nullptr;int(*Py_IsInitialized)()=nullptr;PyObject*(*Py_CompileString)(const char*,const char*,int)=nullptr;PyObject*(*PyObject_GetAttrString)(PyObject*,const char*)=nullptr;Py_ssize_t(*PyTuple_Size)(PyObject*)=nullptr;PyObject*(*PyTuple_GetItem)(PyObject*,Py_ssize_t)=nullptr;int(*PyBytes_AsStringAndSize)(PyObject*,char**,Py_ssize_t*)=nullptr;void(*Py_DecRef)(PyObject*)=nullptr;void(*PyErr_Clear)()=nullptr;int(*Py_FinalizeEx)()=nullptr;const char*(*Py_GetVersion)()=nullptr;
};
bool dump_child_code(ChildApi&a,PyObject*co,const std::string&path,std::ofstream&o,std::string&error,int depth=0){
    if(depth>128){error="compiler-probe code-object recursion limit exceeded";return false;}PyObject*b=a.PyObject_GetAttrString(co,"co_code");if(!b){if(a.PyErr_Clear)a.PyErr_Clear();error="compiled object lacks co_code";return false;}char*p=nullptr;Py_ssize_t n=0;if(a.PyBytes_AsStringAndSize(b,&p,&n)||n<0){a.Py_DecRef(b);if(a.PyErr_Clear)a.PyErr_Clear();error="cannot read co_code bytes";return false;}static const char*hex="0123456789abcdef";o<<"CODE\t"<<path<<'\t';for(Py_ssize_t i=0;i<n;i++){unsigned c=static_cast<unsigned char>(p[i]);o<<hex[c>>4]<<hex[c&15];}o<<'\n';a.Py_DecRef(b);
    PyObject*cs=a.PyObject_GetAttrString(co,"co_consts");if(!cs){if(a.PyErr_Clear)a.PyErr_Clear();error="compiled object lacks co_consts";return false;}auto count=a.PyTuple_Size(cs);if(count<0){a.Py_DecRef(cs);if(a.PyErr_Clear)a.PyErr_Clear();error="co_consts is not a tuple";return false;}for(Py_ssize_t i=0;i<count;i++){PyObject*x=a.PyTuple_GetItem(cs,i);if(!x)continue;PyObject*test=a.PyObject_GetAttrString(x,"co_code");if(!test){if(a.PyErr_Clear)a.PyErr_Clear();continue;}a.Py_DecRef(test);if(!dump_child_code(a,x,path+"."+std::to_string(i),o,error,depth+1)){a.Py_DecRef(cs);return false;}}a.Py_DecRef(cs);return true;
}
}
int cpython_probe_child_main(){
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);int argc=0;LPWSTR*av=CommandLineToArgvW(GetCommandLineW(),&argc);if(!av||argc<5){if(av)LocalFree(av);return 2;}std::filesystem::path dll=av[2],stdlib=av[3],outp=av[4];LocalFree(av);std::ofstream out(outp,std::ios::binary|std::ios::trunc);if(!out)return 3;
    SetDllDirectoryW(dll.parent_path().c_str());HMODULE h=LoadLibraryW(dll.c_str());if(!h){out<<"ERROR\tLoadLibraryW failed "<<GetLastError()<<"\n";return 4;}ChildApi a;a.Py_SetPath=proc<decltype(a.Py_SetPath)>(h,"Py_SetPath");a.Py_Initialize=proc<decltype(a.Py_Initialize)>(h,"Py_Initialize");a.Py_IsInitialized=proc<decltype(a.Py_IsInitialized)>(h,"Py_IsInitialized");a.Py_CompileString=proc<decltype(a.Py_CompileString)>(h,"Py_CompileString");a.PyObject_GetAttrString=proc<decltype(a.PyObject_GetAttrString)>(h,"PyObject_GetAttrString");a.PyTuple_Size=proc<decltype(a.PyTuple_Size)>(h,"PyTuple_Size");a.PyTuple_GetItem=proc<decltype(a.PyTuple_GetItem)>(h,"PyTuple_GetItem");a.PyBytes_AsStringAndSize=proc<decltype(a.PyBytes_AsStringAndSize)>(h,"PyBytes_AsStringAndSize");a.Py_DecRef=proc<decltype(a.Py_DecRef)>(h,"Py_DecRef");a.PyErr_Clear=proc<decltype(a.PyErr_Clear)>(h,"PyErr_Clear");a.Py_FinalizeEx=proc<decltype(a.Py_FinalizeEx)>(h,"Py_FinalizeEx");a.Py_GetVersion=proc<decltype(a.Py_GetVersion)>(h,"Py_GetVersion");
    if(!a.Py_SetPath||!a.Py_Initialize||!a.Py_CompileString||!a.PyObject_GetAttrString||!a.PyTuple_Size||!a.PyTuple_GetItem||!a.PyBytes_AsStringAndSize||!a.Py_DecRef){out<<"ERROR\tmissing required stable CPython C API export\n";FreeLibrary(h);return 5;}
    auto search=stdlib.wstring()+L";"+dll.parent_path().wstring();a.Py_SetPath(search.c_str());out<<"START\t"<<(a.Py_GetVersion?a.Py_GetVersion():"")<<"\n";out.flush();a.Py_Initialize();if(a.Py_IsInitialized&&!a.Py_IsInitialized()){out<<"ERROR\tPy_Initialize did not initialize runtime\n";FreeLibrary(h);return 6;}PyObject*co=a.Py_CompileString(kCPythonCompilerProbeSource,"<auto-refirst-compiler-probe>",257);if(!co){if(a.PyErr_Clear)a.PyErr_Clear();out<<"ERROR\tPy_CompileString failed on compiler probe corpus\n";if(a.Py_FinalizeEx)a.Py_FinalizeEx();FreeLibrary(h);return 7;}std::string err;bool ok=dump_child_code(a,co,"0",out,err);a.Py_DecRef(co);if(ok)out<<"OK\t"<<(a.Py_GetVersion?a.Py_GetVersion():"")<<"\n";else out<<"ERROR\t"<<err<<"\n";out.flush();if(a.Py_FinalizeEx)a.Py_FinalizeEx();FreeLibrary(h);return ok?0:8;
}
bool run_cpython_compiler_probe_for_input(const std::filesystem::path&input,const PyInstArchiveInfo*pyi,CPythonInfo&cp,std::uint32_t timeout_ms,std::string&error){
    cp.compiler_probe=CPythonCompilerProbeInfo{};cp.compiler_probe.attempted=true;TempDir td{make_temp_dir()};if(td.path.empty()){error="cannot create temporary compiler-probe directory";cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}std::filesystem::path dll,stdlib;std::vector<std::uint8_t>runtime_bytes;
    if(cp.source.rfind("CArchive:",0)==0&&pyi&&pyi->valid){
        MappedFile mapped(input);if(!mapped.valid()){error="cannot reopen PyInstaller input for compiler probe: "+mapped.error();cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}auto runtime_name=cp.source.substr(9);auto ri=std::find_if(pyi->entries.begin(),pyi->entries.end(),[&](const PyInstEntry&e){return e.name==runtime_name;});if(ri==pyi->entries.end()){error="embedded CPython runtime entry not found for compiler probe";cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}auto rb=pyinstaller_entry_bytes(mapped.bytes(),*pyi,*ri);if(!rb){error="cannot decompress embedded CPython runtime for compiler probe";cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}runtime_bytes=std::move(*rb);dll=td.path/basename_ascii(runtime_name);if(!write_bytes(dll,runtime_bytes)){error="cannot write temporary CPython runtime";cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}
        auto bi=std::find_if(pyi->entries.begin(),pyi->entries.end(),[](const PyInstEntry&e){return lower_ascii(basename_ascii(e.name))=="base_library.zip";});if(bi==pyi->entries.end()){error="PyInstaller base_library.zip not found for compiler probe";cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}auto bb=pyinstaller_entry_bytes(mapped.bytes(),*pyi,*bi);if(!bb){error="cannot decompress base_library.zip for compiler probe";cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}stdlib=td.path/"base_library.zip";if(!write_bytes(stdlib,*bb)){error="cannot write temporary base_library.zip";cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}
        auto rpe=parse_pe(std::span<const std::uint8_t>(runtime_bytes));for(const auto&im:rpe.imports){auto want=lower_ascii(im.name);auto di=std::find_if(pyi->entries.begin(),pyi->entries.end(),[&](const PyInstEntry&e){return lower_ascii(basename_ascii(e.name))==want;});if(di==pyi->entries.end())continue;auto db=pyinstaller_entry_bytes(mapped.bytes(),*pyi,*di);if(db)write_bytes(td.path/basename_ascii(di->name),*db);}
    }else{
        std::error_code ec;dll=std::filesystem::absolute(input,ec);if(ec)dll=input;auto dir=dll.parent_path().empty()?std::filesystem::current_path():dll.parent_path();auto major=(cp.version_hex>>24)&0xff,minor=(cp.version_hex>>16)&0xff;std::vector<std::filesystem::path>candidates={dir/("python"+std::to_string(major)+std::to_string(minor)+".zip"),dir/"base_library.zip",dir/"python3.zip"};for(const auto&c:candidates)if(std::filesystem::is_regular_file(c,ec)){stdlib=c;break;}if(stdlib.empty()){error="no sibling pythonXY.zip/base_library.zip found for compiler probe";cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}
    }
    auto out=td.path/"probe.txt";DWORD ec=0;if(!run_child(dll,stdlib,out,timeout_ms,ec,error)){cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}cp.compiler_probe.launched=true;std::vector<CPythonCompilerProbeCode>codes;std::string runtime_version,parse_error;if(!parse_probe_output(out,codes,runtime_version,parse_error)){error=parse_error+(ec?"; child exit="+std::to_string(ec):"");cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}
    const auto expected=cp.version;const bool version_ok=!expected.empty()&&runtime_version.rfind(expected,0)==0&&(runtime_version.size()==expected.size()||runtime_version[expected.size()]==' '||runtime_version[expected.size()]=='+'||runtime_version[expected.size()]=='(');
    if(!version_ok){error="compiler-probe runtime version mismatch: static="+expected+" dynamic="+runtime_version;cp.compiler_probe.state="FAILED";cp.compiler_probe.error=error;return false;}
    auto r=compare_cpython_compiler_probe(cp.version_hex,codes);r.launched=true;cp.compiler_probe=std::move(r);if(ec&&!cp.compiler_probe.success){cp.compiler_probe.error += (cp.compiler_probe.error.empty()?"":"; ")+std::string("child exit=")+std::to_string(ec);}return true;
}
#else
int cpython_probe_child_main(){return 2;}
bool run_cpython_compiler_probe_for_input(const std::filesystem::path&,const PyInstArchiveInfo*,CPythonInfo&cp,std::uint32_t,std::string&error){cp.compiler_probe.attempted=true;cp.compiler_probe.state="FAILED";cp.compiler_probe.error="compiler probe execution is only available in the Windows build";error=cp.compiler_probe.error;return false;}
#endif
}
