#include "prts/nested_executable.hpp"
#include "prts/sha256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace prts { namespace {

bool add_u64(std::uint64_t a,std::uint64_t b,std::uint64_t&out){
    if(b>std::numeric_limits<std::uint64_t>::max()-a)return false;
    out=a+b;return true;
}
bool mul_u64(std::uint64_t a,std::uint64_t b,std::uint64_t&out){
    if(a&&b>std::numeric_limits<std::uint64_t>::max()/a)return false;
    out=a*b;return true;
}
bool power2(std::uint64_t x){return x&&!(x&(x-1));}
std::uint64_t align_up(std::uint64_t x,std::uint64_t a){
    if(!a)return x;
    const auto r=x%a;
    if(!r)return x;
    if(a-r>std::numeric_limits<std::uint64_t>::max()-x)return std::numeric_limits<std::uint64_t>::max();
    return x+(a-r);
}

template<class T>
bool rd_le(std::span<const std::uint8_t>d,std::uint64_t off,T&v){
    if(off>d.size()||sizeof(T)>d.size()-static_cast<std::size_t>(off))return false;
    v=0;for(std::size_t i=0;i<sizeof(T);++i)v=static_cast<T>(v|(static_cast<T>(d[static_cast<std::size_t>(off)+i])<<(8*i)));
    return true;
}

bool rd16(std::span<const std::uint8_t>d,std::uint64_t off,bool le,std::uint16_t&v){
    if(off>d.size()||2>d.size()-static_cast<std::size_t>(off))return false;
    const auto p=static_cast<std::size_t>(off);v=le?std::uint16_t(d[p])|(std::uint16_t(d[p+1])<<8):std::uint16_t(d[p+1])|(std::uint16_t(d[p])<<8);return true;
}
bool rd32(std::span<const std::uint8_t>d,std::uint64_t off,bool le,std::uint32_t&v){
    if(off>d.size()||4>d.size()-static_cast<std::size_t>(off))return false;
    const auto p=static_cast<std::size_t>(off);v=0;
    if(le)for(unsigned i=0;i<4;++i)v|=std::uint32_t(d[p+i])<<(8*i);
    else for(unsigned i=0;i<4;++i)v=(v<<8)|d[p+i];
    return true;
}
bool rd64(std::span<const std::uint8_t>d,std::uint64_t off,bool le,std::uint64_t&v){
    if(off>d.size()||8>d.size()-static_cast<std::size_t>(off))return false;
    const auto p=static_cast<std::size_t>(off);v=0;
    if(le)for(unsigned i=0;i<8;++i)v|=std::uint64_t(d[p+i])<<(8*i);
    else for(unsigned i=0;i<8;++i)v=(v<<8)|d[p+i];
    return true;
}

NestedExecutableInfo base_info(std::string format,std::uint64_t off){NestedExecutableInfo x;x.format=std::move(format);x.parent_offset=off;return x;}
NestedExecutableInfo fail(NestedExecutableInfo x,std::string state,std::string error){x.valid=false;x.validation_state=std::move(state);x.error=std::move(error);return x;}

std::string pe_arch(std::uint16_t m){
    switch(m){case 0x014c:return "x86";case 0x8664:return "x86-64";case 0xaa64:return "AArch64";case 0x01c0:case 0x01c2:case 0x01c4:return "ARM";case 0x0200:return "IA64";default:return "PE_MACHINE_"+std::to_string(m);}
}
std::string elf_arch(std::uint16_t m){
    switch(m){case 3:return "x86";case 8:return "MIPS";case 40:return "ARM";case 62:return "x86-64";case 183:return "AArch64";case 243:return "RISC-V";default:return "EM_"+std::to_string(m);}
}

struct PeSectionRaw {
    std::uint32_t rva=0,vsize=0,raw_offset=0,raw_size=0,characteristics=0;
    std::uint64_t raw_end=0,virtual_end=0;
};

NestedExecutableInfo validate_pe(std::span<const std::uint8_t>p,std::uint64_t parent_off,NestedExecutableLimits limits){
    auto out=base_info("PE",parent_off);out.endianness="little";
    if(p.size()<0x40||p[0]!='M'||p[1]!='Z')return fail(std::move(out),"INVALID_HEADER","exact DOS header is absent or truncated");
    std::uint32_t lfanew=0;if(!rd_le(p,0x3c,lfanew)||lfanew<0x40||lfanew>0x100000||lfanew%4)return fail(std::move(out),"INVALID_HEADER","PE e_lfanew is outside the bounded/aligned DOS-to-NT header range");
    std::uint64_t nt_end=0;if(!add_u64(lfanew,24,nt_end)||nt_end>p.size())return fail(std::move(out),"TRUNCATED_HEADER","NT/COFF header extends outside parent bytes");
    if(std::memcmp(p.data()+lfanew,"PE\0\0",4)!=0)return fail(std::move(out),"INVALID_HEADER","PE signature does not close at e_lfanew");
    std::uint16_t machine=0,nsec=0,opt_size=0,characteristics=0;
    std::uint32_t ptr_sym=0,num_sym=0;
    rd_le(p,lfanew+4,machine);rd_le(p,lfanew+6,nsec);rd_le(p,lfanew+12,ptr_sym);rd_le(p,lfanew+16,num_sym);rd_le(p,lfanew+20,opt_size);rd_le(p,lfanew+22,characteristics);
    out.machine=machine;out.architecture=pe_arch(machine);
    if(!machine)return fail(std::move(out),"INVALID_HEADER","PE machine is IMAGE_FILE_MACHINE_UNKNOWN");
    if(!(characteristics&0x0002u))return fail(std::move(out),"INVALID_HEADER","COFF header does not mark an executable image");
    if(!nsec||nsec>96)return fail(std::move(out),"INVALID_HEADER","PE section count is zero or outside the bounded 96-section validator limit");
    const std::uint64_t oo=std::uint64_t(lfanew)+24;
    std::uint64_t opt_end=0;if(!add_u64(oo,opt_size,opt_end)||opt_end>p.size())return fail(std::move(out),"TRUNCATED_HEADER","optional header extends outside parent bytes");
    std::uint16_t magic=0;if(!rd_le(p,oo,magic)||(magic!=0x10b&&magic!=0x20b))return fail(std::move(out),"INVALID_HEADER","unsupported PE optional-header magic");
    out.is_64=magic==0x20b;const std::uint16_t min_opt=out.is_64?112:96;if(opt_size<min_opt)return fail(std::move(out),"TRUNCATED_HEADER","optional header is shorter than its PE32/PE32+ fixed fields");
    if((machine==0x8664||machine==0xaa64||machine==0x0200)&&!out.is_64)return fail(std::move(out),"ARCHITECTURE_CONTRADICTION","64-bit PE machine is paired with a PE32 optional header");
    if((machine==0x014c||machine==0x01c0||machine==0x01c2||machine==0x01c4)&&out.is_64)return fail(std::move(out),"ARCHITECTURE_CONTRADICTION","32-bit PE machine is paired with a PE32+ optional header");
    std::uint32_t entry=0,section_align=0,file_align=0,size_image=0,size_headers=0,num_dirs=0;
    rd_le(p,oo+16,entry);rd_le(p,oo+32,section_align);rd_le(p,oo+36,file_align);rd_le(p,oo+56,size_image);rd_le(p,oo+60,size_headers);rd_le(p,oo+(out.is_64?108:92),num_dirs);
    if(!power2(file_align)||file_align<512||file_align>65536)return fail(std::move(out),"HEADER_GEOMETRY_CONTRADICTION","PE FileAlignment is not a 512..65536 power of two");
    if(!power2(section_align)||section_align<file_align||(section_align<4096&&section_align!=file_align))return fail(std::move(out),"HEADER_GEOMETRY_CONTRADICTION","PE SectionAlignment/FileAlignment relationship is incoherent");
    if(!size_image||size_image%section_align)return fail(std::move(out),"HEADER_GEOMETRY_CONTRADICTION","SizeOfImage is zero or not SectionAlignment-aligned");
    if(!size_headers||size_headers%file_align||size_headers>p.size())return fail(std::move(out),"TRUNCATED_HEADER","SizeOfHeaders is zero, misaligned, or not file-backed");
    const std::uint64_t dd_start=oo+(out.is_64?112:96);
    if(num_dirs>(opt_end-dd_start)/8)return fail(std::move(out),"TRUNCATED_HEADER","NumberOfRvaAndSizes exceeds bytes present in the optional header");
    std::uint64_t sec_bytes=0,sec_table_end=0;if(!mul_u64(nsec,40,sec_bytes)||!add_u64(opt_end,sec_bytes,sec_table_end)||sec_table_end>p.size())return fail(std::move(out),"TRUNCATED_SECTION_TABLE","complete PE section table is not file-backed");
    if(sec_table_end>size_headers)return fail(std::move(out),"HEADER_GEOMETRY_CONTRADICTION","SizeOfHeaders does not cover the complete section table");

    std::vector<PeSectionRaw> sections;sections.reserve(nsec);std::uint64_t exact_end=size_headers;
    for(std::uint16_t i=0;i<nsec;++i){
        const auto sh=opt_end+std::uint64_t(i)*40;PeSectionRaw s;
        rd_le(p,sh+8,s.vsize);rd_le(p,sh+12,s.rva);rd_le(p,sh+16,s.raw_size);rd_le(p,sh+20,s.raw_offset);rd_le(p,sh+36,s.characteristics);
        if(!s.rva||s.rva%section_align)return fail(std::move(out),"SECTION_GEOMETRY_CONTRADICTION","PE section RVA is zero or not SectionAlignment-aligned");
        const auto mem_size=std::max(s.vsize,s.raw_size);if(mem_size){if(!add_u64(s.rva,mem_size,s.virtual_end)||s.virtual_end>size_image)return fail(std::move(out),"SECTION_GEOMETRY_CONTRADICTION","PE section virtual extent exceeds SizeOfImage");}
        if(s.raw_size){
            if(s.raw_size%file_align)return fail(std::move(out),"SECTION_GEOMETRY_CONTRADICTION","PE section SizeOfRawData is not FileAlignment-aligned");
            if(!s.raw_offset||s.raw_offset< size_headers||s.raw_offset%file_align)return fail(std::move(out),"IMPOSSIBLE_RAW_OFFSET","PE section raw range starts in headers, at zero, or off FileAlignment");
            if(!add_u64(s.raw_offset,s.raw_size,s.raw_end)||s.raw_end>p.size())return fail(std::move(out),"TRUNCATED_SECTION","declared PE section raw range extends outside parent bytes");
            if(s.raw_end>limits.max_child_bytes)return fail(std::move(out),"SIZE_LIMIT","declared PE section extent exceeds the one-child safety ceiling");
            exact_end=std::max(exact_end,s.raw_end);
        }
        sections.push_back(s);
    }
    {
        std::vector<std::pair<std::uint64_t,std::uint64_t>> ranges,vranges;
        for(const auto&s:sections){if(s.raw_size)ranges.emplace_back(s.raw_offset,s.raw_end);if(s.virtual_end>s.rva)vranges.emplace_back(s.rva,s.virtual_end);}
        auto overlaps=[](auto v){std::sort(v.begin(),v.end());for(std::size_t i=1;i<v.size();++i)if(v[i].first<v[i-1].second)return true;return false;};
        if(overlaps(ranges))return fail(std::move(out),"OVERLAP_CONTRADICTION","PE sections have overlapping file-backed raw ranges");
        if(overlaps(vranges))return fail(std::move(out),"OVERLAP_CONTRADICTION","PE sections have overlapping virtual ranges");
    }
    if(entry){
        bool entry_exec=false,entry_file=false;for(const auto&s:sections){if(entry<s.rva||entry>=s.virtual_end)continue;entry_exec=(s.characteristics&0x20000000u)!=0;const auto delta=std::uint64_t(entry)-s.rva;entry_file=s.raw_size&&delta<s.raw_size&&std::uint64_t(s.raw_offset)+delta<p.size();break;}
        if(!entry_exec||!entry_file)return fail(std::move(out),"ENTRY_RELATION_CONTRADICTION","PE entry point is not file-backed inside an executable section");
    }else if(!(characteristics&0x2000u))return fail(std::move(out),"ENTRY_RELATION_CONTRADICTION","non-DLL PE has a zero entry point");

    auto dir=[&](std::uint32_t idx,std::uint32_t&rva,std::uint32_t&size)->bool{
        rva=size=0;if(idx>=num_dirs)return true;return rd_le(p,dd_start+std::uint64_t(idx)*8,rva)&&rd_le(p,dd_start+std::uint64_t(idx)*8+4,size);
    };
    std::uint32_t cert_off=0,cert_size=0;if(!dir(4,cert_off,cert_size))return fail(std::move(out),"TRUNCATED_HEADER","security data-directory entry is truncated");
    if(bool(cert_off)!=bool(cert_size))return fail(std::move(out),"CERTIFICATE_CONTRADICTION","PE security directory has only one of file offset/size");
    if(cert_size){
        if(cert_off%8||cert_size<8)return fail(std::move(out),"CERTIFICATE_CONTRADICTION","certificate table file offset/size violates WIN_CERTIFICATE alignment/minimum geometry");
        std::uint64_t cert_end=0;if(!add_u64(cert_off,cert_size,cert_end)||cert_end>p.size())return fail(std::move(out),"TRUNCATED_CERTIFICATE","PE certificate table extends outside parent bytes");
        for(const auto&s:sections)if(s.raw_size&&cert_off<s.raw_end&&s.raw_offset<cert_end)return fail(std::move(out),"CERTIFICATE_CONTRADICTION","certificate table overlaps a mapped section raw range");
        std::uint64_t q=cert_off;while(q<cert_end){if(cert_end-q<8)return fail(std::move(out),"CERTIFICATE_CONTRADICTION","trailing certificate bytes cannot hold a WIN_CERTIFICATE header");std::uint32_t len=0;rd_le(p,q,len);if(len<8||len>cert_end-q)return fail(std::move(out),"CERTIFICATE_CONTRADICTION","WIN_CERTIFICATE length escapes the declared security directory");const auto next=align_up(q+len,8);if(next==std::numeric_limits<std::uint64_t>::max()||next>cert_end)return fail(std::move(out),"CERTIFICATE_CONTRADICTION","WIN_CERTIFICATE padding escapes the declared security directory");q=next;}
        exact_end=std::max(exact_end,cert_end);
    }

    if(bool(ptr_sym)!=bool(num_sym))return fail(std::move(out),"COFF_SYMBOL_CONTRADICTION","COFF symbol pointer/count are not jointly present");
    if(ptr_sym){
        std::uint64_t sym_bytes=0,sym_end=0;if(!mul_u64(num_sym,18,sym_bytes)||!add_u64(ptr_sym,sym_bytes,sym_end)||sym_end>p.size()||p.size()-static_cast<std::size_t>(sym_end)<4)return fail(std::move(out),"TRUNCATED_COFF_SYMBOLS","COFF symbol/string table is not completely file-backed");
        std::uint32_t str_len=0;rd_le(p,sym_end,str_len);if(str_len<4)return fail(std::move(out),"COFF_SYMBOL_CONTRADICTION","COFF string table length is smaller than its length word");std::uint64_t str_end=0;if(!add_u64(sym_end,str_len,str_end)||str_end>p.size())return fail(std::move(out),"TRUNCATED_COFF_SYMBOLS","COFF string table extends outside parent bytes");exact_end=std::max(exact_end,str_end);
    }

    // IMAGE_DIRECTORY_ENTRY_DEBUG points to an in-image directory, while each
    // IMAGE_DEBUG_DIRECTORY may own raw data outside section ranges. Include only
    // those explicitly pointed-to bytes, never arbitrary overlay.
    std::uint32_t debug_rva=0,debug_size=0;if(!dir(6,debug_rva,debug_size))return fail(std::move(out),"TRUNCATED_HEADER","debug data-directory entry is truncated");
    if(bool(debug_rva)!=bool(debug_size))return fail(std::move(out),"DEBUG_DIRECTORY_CONTRADICTION","PE debug directory has only one of RVA/size");
    if(debug_size){
        if(debug_size%28)return fail(std::move(out),"DEBUG_DIRECTORY_CONTRADICTION","PE debug directory size is not an array of IMAGE_DEBUG_DIRECTORY records");
        auto map_rva=[&](std::uint32_t rva,std::uint32_t size)->std::optional<std::uint64_t>{
            if(rva<size_headers&&std::uint64_t(size)<=size_headers-rva)return rva;
            for(const auto&s:sections){if(rva<s.rva)continue;const auto delta=std::uint64_t(rva)-s.rva;if(delta<=s.raw_size&&std::uint64_t(size)<=std::uint64_t(s.raw_size)-delta)return std::uint64_t(s.raw_offset)+delta;}return std::nullopt;
        };
        auto debug_off=map_rva(debug_rva,debug_size);if(!debug_off||*debug_off>p.size()||debug_size>p.size()-static_cast<std::size_t>(*debug_off))return fail(std::move(out),"DEBUG_DIRECTORY_CONTRADICTION","PE debug directory RVA is not wholly file-backed");
        for(std::uint32_t i=0;i<debug_size/28;++i){const auto q=*debug_off+std::uint64_t(i)*28;std::uint32_t data_size=0,data_off=0;rd_le(p,q+16,data_size);rd_le(p,q+24,data_off);if(bool(data_size)!=bool(data_off))return fail(std::move(out),"DEBUG_DIRECTORY_CONTRADICTION","debug raw-data pointer/size are not jointly present");if(data_size){std::uint64_t e=0;if(!add_u64(data_off,data_size,e)||e>p.size())return fail(std::move(out),"TRUNCATED_DEBUG_DATA","debug raw-data range extends outside parent bytes");exact_end=std::max(exact_end,e);}}
    }

    if(exact_end<size_headers||exact_end>p.size())return fail(std::move(out),"UNRESOLVED_EXTENT","PE declared file extent does not close inside parent bytes");
    if(exact_end>limits.max_child_bytes)return fail(std::move(out),"SIZE_LIMIT","validated PE exact extent exceeds the one-child safety ceiling");
    out.exact_size=exact_end;out.child_sha256=sha256_bytes(p.first(static_cast<std::size_t>(exact_end)));out.valid=true;out.validation_state="VALIDATED_EXACT";return out;
}

struct ElfLoad {std::uint64_t off=0,file_size=0,vaddr=0,mem_size=0;std::uint32_t flags=0;};
struct ElfSectionRaw {std::uint32_t type=0;std::uint64_t flags=0,addr=0,off=0,size=0,align=0,entsize=0;std::uint32_t link=0;};

NestedExecutableInfo validate_elf(std::span<const std::uint8_t>p,std::uint64_t parent_off,NestedExecutableLimits limits){
    auto out=base_info("ELF",parent_off);
    if(p.size()<16||p[0]!=0x7f||p[1]!='E'||p[2]!='L'||p[3]!='F')return fail(std::move(out),"INVALID_HEADER","ELF identification magic is absent");
    const auto cls=p[4],data=p[5],ident_ver=p[6];if((cls!=1&&cls!=2)||(data!=1&&data!=2)||ident_ver!=1)return fail(std::move(out),"INVALID_HEADER","ELF class/endian/ident version is unsupported or invalid");
    out.is_64=cls==2;const bool le=data==1;out.endianness=le?"little":"big";const std::uint16_t eh_expected=out.is_64?64:52,ph_expected=out.is_64?56:32,sh_expected=out.is_64?64:40;
    if(p.size()<eh_expected)return fail(std::move(out),"TRUNCATED_HEADER","complete ELF header is not file-backed");
    std::uint16_t type=0,machine=0,ehsize=0,phentsize=0,phnum=0,shentsize=0,shnum=0,shstrndx=0;std::uint32_t version=0;std::uint64_t entry=0,phoff=0,shoff=0;
    rd16(p,16,le,type);rd16(p,18,le,machine);rd32(p,20,le,version);out.machine=machine;out.architecture=elf_arch(machine);
    if(out.is_64){rd64(p,24,le,entry);rd64(p,32,le,phoff);rd64(p,40,le,shoff);rd16(p,52,le,ehsize);rd16(p,54,le,phentsize);rd16(p,56,le,phnum);rd16(p,58,le,shentsize);rd16(p,60,le,shnum);rd16(p,62,le,shstrndx);}
    else{std::uint32_t x=0;rd32(p,24,le,x);entry=x;rd32(p,28,le,x);phoff=x;rd32(p,32,le,x);shoff=x;rd16(p,40,le,ehsize);rd16(p,42,le,phentsize);rd16(p,44,le,phnum);rd16(p,46,le,shentsize);rd16(p,48,le,shnum);rd16(p,50,le,shstrndx);}
    if(version!=1||!machine)return fail(std::move(out),"INVALID_HEADER","ELF version/machine is invalid");
    if(type!=2&&type!=3)return fail(std::move(out),"NOT_EXECUTABLE_IMAGE","ELF child is neither ET_EXEC nor ET_DYN");
    if(ehsize!=eh_expected)return fail(std::move(out),"HEADER_GEOMETRY_CONTRADICTION","ELF e_ehsize does not equal the class-defined header size");
    if(phnum==0||phnum==0xffff)return fail(std::move(out),"UNRESOLVED_EXTENDED_NUMBERING","ELF has no program headers or uses unsupported PN_XNUM extended numbering");
    if(phentsize!=ph_expected)return fail(std::move(out),"HEADER_GEOMETRY_CONTRADICTION","ELF e_phentsize does not equal the class-defined program-header size");
    std::uint64_t phbytes=0,phend=0;if(!mul_u64(phnum,phentsize,phbytes)||!add_u64(phoff,phbytes,phend)||phoff<ehsize||phend>p.size())return fail(std::move(out),"TRUNCATED_PROGRAM_HEADERS","complete ELF program-header table is not file-backed");
    std::uint64_t exact_end=std::max<std::uint64_t>(ehsize,phend);std::vector<ElfLoad> loads;
    for(std::uint16_t i=0;i<phnum;++i){
        const auto q=phoff+std::uint64_t(i)*phentsize;std::uint32_t pt=0,flags=0;std::uint64_t off=0,va=0,fs=0,ms=0,al=0;rd32(p,q,le,pt);
        if(out.is_64){rd32(p,q+4,le,flags);rd64(p,q+8,le,off);rd64(p,q+16,le,va);rd64(p,q+32,le,fs);rd64(p,q+40,le,ms);rd64(p,q+48,le,al);}else{std::uint32_t x=0;rd32(p,q+4,le,x);off=x;rd32(p,q+8,le,x);va=x;rd32(p,q+16,le,x);fs=x;rd32(p,q+20,le,x);ms=x;rd32(p,q+24,le,flags);rd32(p,q+28,le,x);al=x;}
        if(al>1&&!power2(al))return fail(std::move(out),"SEGMENT_GEOMETRY_CONTRADICTION","ELF segment p_align is not zero/one/power-of-two");
        if(fs){std::uint64_t e=0;if(!add_u64(off,fs,e)||e>p.size())return fail(std::move(out),"TRUNCATED_SEGMENT","declared ELF file-backed segment extends outside parent bytes");if(e>limits.max_child_bytes)return fail(std::move(out),"SIZE_LIMIT","declared ELF segment extent exceeds the one-child safety ceiling");exact_end=std::max(exact_end,e);}
        if(pt==1){if(fs>ms)return fail(std::move(out),"SEGMENT_GEOMETRY_CONTRADICTION","ELF PT_LOAD has p_filesz greater than p_memsz");if(al>1&&(off%al)!=(va%al))return fail(std::move(out),"SEGMENT_GEOMETRY_CONTRADICTION","ELF PT_LOAD p_offset/p_vaddr are incongruent modulo p_align");loads.push_back({off,fs,va,ms,flags});}
    }
    if(loads.empty())return fail(std::move(out),"SEGMENT_GEOMETRY_CONTRADICTION","ELF executable has no PT_LOAD segment");
    {
        std::vector<std::pair<std::uint64_t,std::uint64_t>> raw,virt;for(const auto&l:loads){std::uint64_t e=0;if(l.file_size){add_u64(l.off,l.file_size,e);raw.emplace_back(l.off,e);}if(l.mem_size){if(!add_u64(l.vaddr,l.mem_size,e))return fail(std::move(out),"SEGMENT_GEOMETRY_CONTRADICTION","ELF PT_LOAD virtual extent overflows address space");virt.emplace_back(l.vaddr,e);}}
        auto overlaps=[](auto v){std::sort(v.begin(),v.end());for(std::size_t i=1;i<v.size();++i)if(v[i].first<v[i-1].second)return true;return false;};
        if(overlaps(raw)||overlaps(virt))return fail(std::move(out),"OVERLAP_CONTRADICTION","ELF PT_LOAD segments overlap in file or virtual address space");
    }
    if(entry){bool ok=false;for(const auto&l:loads){if(!(l.flags&1)||entry<l.vaddr)continue;const auto delta=entry-l.vaddr;if(delta<l.file_size){ok=true;break;}}if(!ok)return fail(std::move(out),"ENTRY_RELATION_CONTRADICTION","ELF entry is not file-backed by an executable PT_LOAD segment");}
    else if(type==2)return fail(std::move(out),"ENTRY_RELATION_CONTRADICTION","ET_EXEC has a zero entry point");

    if(shoff==0){if(shnum||shstrndx)return fail(std::move(out),"SECTION_TABLE_CONTRADICTION","ELF omits e_shoff but declares section headers/string table");}
    else{
        if(shnum==0||shstrndx==0xffff)return fail(std::move(out),"UNRESOLVED_EXTENDED_NUMBERING","ELF section table uses unsupported extended numbering");
        if(shentsize!=sh_expected)return fail(std::move(out),"HEADER_GEOMETRY_CONTRADICTION","ELF e_shentsize does not equal the class-defined section-header size");
        std::uint64_t shbytes=0,shend=0;if(!mul_u64(shnum,shentsize,shbytes)||!add_u64(shoff,shbytes,shend)||shend>p.size())return fail(std::move(out),"TRUNCATED_SECTION_TABLE","complete ELF section-header table is not file-backed");exact_end=std::max(exact_end,shend);
        if(shstrndx>=shnum&&shstrndx!=0)return fail(std::move(out),"SECTION_TABLE_CONTRADICTION","ELF e_shstrndx is outside the section table");
        std::vector<ElfSectionRaw> secs;secs.reserve(shnum);std::vector<std::pair<std::uint64_t,std::uint64_t>> raw;
        for(std::uint16_t i=0;i<shnum;++i){const auto q=shoff+std::uint64_t(i)*shentsize;ElfSectionRaw s;std::uint32_t name=0,info=0;rd32(p,q,le,name);rd32(p,q+4,le,s.type);(void)name;(void)info;
            if(out.is_64){rd64(p,q+8,le,s.flags);rd64(p,q+16,le,s.addr);rd64(p,q+24,le,s.off);rd64(p,q+32,le,s.size);rd32(p,q+40,le,s.link);rd32(p,q+44,le,info);rd64(p,q+48,le,s.align);rd64(p,q+56,le,s.entsize);}else{std::uint32_t x=0;rd32(p,q+8,le,x);s.flags=x;rd32(p,q+12,le,x);s.addr=x;rd32(p,q+16,le,x);s.off=x;rd32(p,q+20,le,x);s.size=x;rd32(p,q+24,le,s.link);rd32(p,q+28,le,info);rd32(p,q+32,le,x);s.align=x;rd32(p,q+36,le,x);s.entsize=x;}
            if(s.link>=shnum&&s.link!=0)return fail(std::move(out),"SECTION_TABLE_CONTRADICTION","ELF section sh_link points outside the section table");
            if(s.align>1&&!power2(s.align))return fail(std::move(out),"SECTION_GEOMETRY_CONTRADICTION","ELF section sh_addralign is not zero/one/power-of-two");
            if(s.entsize&&s.size%s.entsize)return fail(std::move(out),"SECTION_GEOMETRY_CONTRADICTION","ELF section size is not a multiple of nonzero sh_entsize");
            if(s.type!=8&&s.size){std::uint64_t e=0;if(!add_u64(s.off,s.size,e)||e>p.size())return fail(std::move(out),"TRUNCATED_SECTION","declared ELF file-backed section extends outside parent bytes");if(e>limits.max_child_bytes)return fail(std::move(out),"SIZE_LIMIT","declared ELF section extent exceeds the one-child safety ceiling");raw.emplace_back(s.off,e);exact_end=std::max(exact_end,e);}
            secs.push_back(s);
        }
        std::sort(raw.begin(),raw.end());for(std::size_t i=1;i<raw.size();++i)if(raw[i].first<raw[i-1].second)return fail(std::move(out),"OVERLAP_CONTRADICTION","ELF file-backed sections overlap");
        if(shstrndx&&secs[shstrndx].type!=3)return fail(std::move(out),"SECTION_TABLE_CONTRADICTION","ELF section-name string-table index does not reference SHT_STRTAB");
        // Allocated sections must agree with the PT_LOAD mapping. Non-allocated
        // symbols/debug/string tables may legitimately live outside PT_LOAD.
        for(const auto&s:secs){if(!(s.flags&0x2)||!s.size)continue;bool mapped=false;for(const auto&l:loads){if(s.addr<l.vaddr)continue;const auto delta=s.addr-l.vaddr;if(delta>l.mem_size||s.size>l.mem_size-delta)continue;if(s.type==8){mapped=true;break;}if(delta<=l.file_size&&s.size<=l.file_size-delta&&s.off==l.off+delta){mapped=true;break;}}if(!mapped)return fail(std::move(out),"SECTION_SEGMENT_CONTRADICTION","SHF_ALLOC section is not coherently covered by a PT_LOAD mapping");}
    }
    if(exact_end>p.size())return fail(std::move(out),"UNRESOLVED_EXTENT","ELF declared file extent does not close inside parent bytes");
    if(exact_end>limits.max_child_bytes)return fail(std::move(out),"SIZE_LIMIT","validated ELF exact extent exceeds the one-child safety ceiling");
    out.exact_size=exact_end;out.child_sha256=sha256_bytes(p.first(static_cast<std::size_t>(exact_end)));out.valid=true;out.validation_state="VALIDATED_EXACT";return out;
}

} // namespace

NestedExecutableReuseDecision select_nested_executable_reuse(const NestedExecutableInfo&info,std::span<const NestedExecutableArtifactCandidate>candidates){
    NestedExecutableReuseDecision out;
    if(!info.valid||info.validation_state!="VALIDATED_EXACT"||!info.exact_size||info.child_sha256.empty())return out;
    for(std::size_t i=0;i<candidates.size();++i){
        const auto&c=candidates[i];const bool materialized=c.state=="MATERIALIZED"||c.state=="MATERIALIZED_NORMALIZED"||c.state=="VALIDATED_EXACT_STRUCTURED_MEMBER";
        if(!c.validated_structured_member||!materialized||c.path.empty()||c.sha256!=info.child_sha256||c.size!=info.exact_size)continue;
        std::error_code ec;const auto st=std::filesystem::symlink_status(c.path,ec);
        if(ec||st.type()==std::filesystem::file_type::symlink||st.type()!=std::filesystem::file_type::regular)continue;
        const auto n=std::filesystem::file_size(c.path,ec);if(ec||n!=info.exact_size)continue;
        if(sha256_file(c.path)!=info.child_sha256)continue;
        out.matching_indexes.push_back(i);
    }
    if(out.matching_indexes.empty())return out;
    auto less=[&](std::size_t a,std::size_t b){
        const auto&A=candidates[a],&B=candidates[b];const bool ah=A.priority=="HIGH",bh=B.priority=="HIGH";
        if(ah!=bh)return ah>bh;if(A.source!=B.source)return A.source<B.source;if(A.relation!=B.relation)return A.relation<B.relation;
        return A.path.lexically_normal().generic_string()<B.path.lexically_normal().generic_string();
    };
    std::stable_sort(out.matching_indexes.begin(),out.matching_indexes.end(),less);
    out.reuse=true;out.preferred_index=out.matching_indexes.front();out.priority_upgrade_required=candidates[out.preferred_index].priority!="HIGH";return out;
}

NestedExecutableInfo validate_nested_executable(std::span<const std::uint8_t>parent,std::uint64_t parent_offset,std::string_view expected_format,NestedExecutableLimits limits){
    if(parent_offset>=parent.size()){auto x=base_info(std::string(expected_format),parent_offset);return fail(std::move(x),"OUTSIDE_PARENT","candidate offset is outside parent bytes");}
    if(!limits.max_child_bytes){auto x=base_info(std::string(expected_format),parent_offset);return fail(std::move(x),"SIZE_LIMIT","one-child safety ceiling is zero");}
    const auto child=parent.subspan(static_cast<std::size_t>(parent_offset));
    if(expected_format=="PE")return validate_pe(child,parent_offset,limits);
    if(expected_format=="ELF")return validate_elf(child,parent_offset,limits);
    auto x=base_info(std::string(expected_format),parent_offset);return fail(std::move(x),"UNSUPPORTED_FORMAT","nested executable validator only accepts PE or ELF candidates");
}

bool materialize_nested_executable(std::span<const std::uint8_t>parent,const NestedExecutableInfo&info,const std::filesystem::path&output,std::string&error){
    error.clear();if(!info.valid||info.validation_state!="VALIDATED_EXACT"||!info.exact_size){error="nested executable is not in VALIDATED_EXACT state";return false;}
    if(info.parent_offset>parent.size()||info.exact_size>parent.size()-static_cast<std::size_t>(info.parent_offset)){error="validated nested executable extent no longer fits parent bytes";return false;}
    const auto bytes=parent.subspan(static_cast<std::size_t>(info.parent_offset),static_cast<std::size_t>(info.exact_size));
    if(sha256_bytes(bytes)!=info.child_sha256){error="validated nested executable bytes changed before materialization";return false;}
    std::ofstream f(output,std::ios::binary|std::ios::trunc);if(!f){error="cannot create nested executable artifact";return false;}
    f.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));f.close();if(!f){error="nested executable artifact write failed";std::error_code ec;std::filesystem::remove(output,ec);return false;}
    return true;
}

} // namespace prts
