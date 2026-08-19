#include "prts/cpython_frozen_gate.hpp"
#include "prts/cpython_frozen_reference.hpp"
namespace prts {
CPythonFrozenReferenceGate apply_cpython_frozen_reference_if_comparable(CPythonFrozenInfo&frozen,
                                                                         const CPythonInfo&cpython){
    CPythonFrozenReferenceGate out;
    if(!cpython.valid){out.state="UNAVAILABLE_NO_CPYTHON";return out;}
    if(!cpython.exact_reference_available||cpython.reference_version.empty()){
        out.state="UNAVAILABLE_NO_EXACT_REFERENCE";return out;
    }
    out.reference_version=cpython.reference_version;
    if(cpython.reference_status=="REFERENCE_MATCH"){
        out.allowed=true;out.state="REFERENCE_READY_EXACT";
    }else if(cpython.reference_status=="DIFFERS_FROM_OFFICIAL_REFERENCE"&&
             cpython.semantic_reference_status=="COMPARABLE"){
        out.allowed=true;out.state="REFERENCE_READY_SEMANTIC_COMPARABLE";
    }else if(cpython.semantic_reference_status=="BUILD_INCOMPARABLE"){
        out.state="UNAVAILABLE_BUILD_INCOMPARABLE";
    }else if(cpython.semantic_reference_status=="NO_USABLE_PROBES"){
        out.state="UNAVAILABLE_NO_USABLE_PROBES";
    }else{
        out.state="UNAVAILABLE_REFERENCE_NOT_COMPARABLE";
    }
    if(out.allowed)apply_cpython_frozen_reference(frozen,out.reference_version);
    return out;
}
}
