#include "prts/cpython_static.hpp"
namespace prts {
CPythonStaticInfo analyze_cpython_static(std::span<const std::uint8_t>d,
                                         const PeInfo&pe,
                                         bool pyinstaller_user_payload_present,
                                         const std::string&source){
    CPythonStaticInfo out;
    out.runtime=detect_cpython(d,pe,source);
    out.extension=analyze_cpython_extension(d,pe);
    out.cython=analyze_cpython_cython(d,pe,out.extension);

    if(out.runtime.valid){
        const auto minor=int((out.runtime.version_hex>>16)&0xffu);
        out.frozen=analyze_cpython_frozen(d,pe,300+minor);
        out.frozen_reference_gate=apply_cpython_frozen_reference_if_comparable(out.frozen,out.runtime);
    }else{
        out.frozen.state="NO_CPYTHON_RUNTIME";
        out.frozen_reference_gate=apply_cpython_frozen_reference_if_comparable(out.frozen,out.runtime);
    }
    out.priority=build_cpython_frozen_priority(out.frozen,pyinstaller_user_payload_present);

    if(out.cython.valid){out.valid=true;out.state="CYTHON_EXTENSION";}
    else if(out.runtime.valid&&out.extension.valid){out.valid=true;out.state="CPYTHON_RUNTIME_WITH_REGISTRATIONS";}
    else if(out.runtime.valid){out.valid=true;out.state="CPYTHON_RUNTIME";}
    else if(out.extension.valid){out.valid=true;out.state="CPYTHON_EXTENSION";}
    else out.state="NO_CPYTHON_STATIC";
    return out;
}
}
