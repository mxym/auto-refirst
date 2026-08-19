#include "prts/authenticode.hpp"
#include "prts/sha1.hpp"
#include "prts/sha256.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <optional>
#include <sstream>
#include <tuple>
#include <vector>

namespace prts { namespace {
template<class T>bool rd(std::span<const std::uint8_t>d,std::size_t o,T&v){if(o>d.size()||sizeof(T)>d.size()-o)return false;std::memcpy(&v,d.data()+o,sizeof(T));return true;}
std::string hex_bytes(std::span<const std::uint8_t>d){std::ostringstream o;o<<std::hex<<std::setfill('0');for(auto b:d)o<<std::setw(2)<<unsigned(b);return o.str();}
std::string hex20(const std::array<std::uint8_t,20>&a){return hex_bytes(a);}
struct Der {std::uint8_t tag=0;std::size_t begin=0,content=0,length=0,end=0;};
bool der_one(std::span<const std::uint8_t>d,std::size_t&p,Der&n){
    if(p>=d.size())return false;
    n.begin=p;n.tag=d[p++];
    if((n.tag&0x1f)==0x1f||p>=d.size())return false;
    const auto b=d[p++];std::uint64_t len=0;
    if(!(b&0x80))len=b;
    else{const unsigned bytes=unsigned(b&0x7f);if(!bytes||bytes>8||p+bytes>d.size())return false;if(bytes>1&&d[p]==0)return false;for(unsigned i=0;i<bytes;++i){if(len>(~std::uint64_t(0)>>8))return false;len=(len<<8)|d[p++];}if(len<128)return false;}
    if(len>d.size()-p)return false;
    n.content=p;n.length=static_cast<std::size_t>(len);n.end=p+n.length;p=n.end;return true;
}
std::vector<Der> children(std::span<const std::uint8_t>d,const Der&n,bool&ok){std::vector<Der>v;ok=false;if(n.content+n.length>d.size())return v;std::size_t p=n.content;while(p<n.end){Der x;if(!der_one(d,p,x))return v;v.push_back(x);}ok=p==n.end;return v;}
constexpr std::array<std::uint8_t,9> OID_SIGNED_DATA{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02};
constexpr std::array<std::uint8_t,10> OID_SPC_INDIRECT{0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x04};
constexpr std::array<std::uint8_t,5> OID_SHA1{0x2b,0x0e,0x03,0x02,0x1a};
constexpr std::array<std::uint8_t,9> OID_SHA256{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};
constexpr std::array<std::uint8_t,10> OID_SPC_PE_IMAGE{0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x0f};
constexpr std::array<std::uint8_t,10> OID_PAGE_HASH_V1{0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x03,0x01};
constexpr std::array<std::uint8_t,10> OID_PAGE_HASH_V2{0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x03,0x02};
constexpr std::array<std::uint8_t,10> OID_NESTED_SIGNATURE{0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x04,0x01};
constexpr std::array<std::uint8_t,16> PAGE_HASH_CLASSID{0xa6,0xb5,0x86,0xd5,0xb4,0xa1,0x24,0x66,0xae,0x05,0xa2,0x17,0xda,0x8e,0x60,0xd6};
constexpr std::array<std::uint8_t,11> OID_TST_INFO{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x10,0x01,0x04};
template<std::size_t N>bool oid_arr(std::span<const std::uint8_t>d,const Der&n,const std::array<std::uint8_t,N>&a){return n.tag==0x06&&n.length==N&&std::equal(a.begin(),a.end(),d.begin()+static_cast<std::ptrdiff_t>(n.content));}

std::string oid_text(std::span<const std::uint8_t>d,const Der&n){
    if(n.tag!=0x06||!n.length)return{};
    auto b=d.subspan(n.content,n.length);std::ostringstream o;unsigned first=b[0];o<<(first<80?first/40:2)<<'.'<<(first<80?first%40:first-80);std::uint64_t v=0;bool open=false;
    for(std::size_t i=1;i<b.size();++i){auto x=b[i];if(v>(~std::uint64_t(0)>>7))return{};v=(v<<7)|(x&0x7f);open=true;if(!(x&0x80)){o<<'.'<<v;v=0;open=false;}}
    return open?std::string():o.str();
}
std::string asn1_string(std::span<const std::uint8_t>d,const Der&n){
    if(n.content+n.length>d.size())return{};
    auto b=d.subspan(n.content,n.length);
    if(n.tag==0x0c||n.tag==0x13||n.tag==0x14||n.tag==0x16||n.tag==0x12||n.tag==0x1a)return std::string(reinterpret_cast<const char*>(b.data()),b.size());
    if(n.tag==0x1e){std::string o;for(std::size_t i=0;i+1<b.size();i+=2){auto cp=(std::uint16_t(b[i])<<8)|b[i+1];if(cp<0x80)o.push_back(char(cp));else if(cp<0x800){o.push_back(char(0xc0|(cp>>6)));o.push_back(char(0x80|(cp&0x3f)));}else{o.push_back(char(0xe0|(cp>>12)));o.push_back(char(0x80|((cp>>6)&0x3f)));o.push_back(char(0x80|(cp&0x3f)));}}return o;}
    return "#"+hex_bytes(b);
}
std::string name_label(const std::string&o){if(o=="2.5.4.3")return"CN";if(o=="2.5.4.6")return"C";if(o=="2.5.4.7")return"L";if(o=="2.5.4.8")return"ST";if(o=="2.5.4.10")return"O";if(o=="2.5.4.11")return"OU";if(o=="2.5.4.5")return"SERIALNUMBER";if(o=="1.2.840.113549.1.9.1")return"E";return o;}
std::string parse_name(std::span<const std::uint8_t>d,const Der&name){
    bool ok=false;auto rdns=children(d,name,ok);if(!ok)return{};std::ostringstream o;bool first=true;
    for(const auto&set:rdns){if(set.tag!=0x31)continue;auto attrs=children(d,set,ok);if(!ok)return{};for(const auto&a:attrs){if(a.tag!=0x30)continue;auto av=children(d,a,ok);if(!ok||av.size()!=2||av[0].tag!=0x06)continue;auto oid=oid_text(d,av[0]);auto val=asn1_string(d,av[1]);if(!first)o<<", ";first=false;o<<name_label(oid)<<'='<<val;}}
    return o.str();
}
std::string integer_hex(std::span<const std::uint8_t>d,const Der&n){if(n.tag!=0x02||!n.length)return{};auto b=d.subspan(n.content,n.length);while(b.size()>1&&b.front()==0)b=b.subspan(1);return hex_bytes(b);}
bool der_same(std::span<const std::uint8_t>d,const Der&a,const Der&b){if(a.end<a.begin||b.end<b.begin||a.end>d.size()||b.end>d.size()||a.end-a.begin!=b.end-b.begin)return false;return std::equal(d.begin()+static_cast<std::ptrdiff_t>(a.begin),d.begin()+static_cast<std::ptrdiff_t>(a.end),d.begin()+static_cast<std::ptrdiff_t>(b.begin));}
std::string time_text(std::span<const std::uint8_t>d,const Der&t){if(t.tag!=0x17&&t.tag!=0x18)return{};auto raw=std::string(reinterpret_cast<const char*>(d.data()+t.content),t.length);if(raw.empty()||raw.back()!='Z')return raw;auto digits=raw.substr(0,raw.size()-1);std::string y,rest;if(t.tag==0x17&&digits.size()>=10){int yy=(digits[0]-'0')*10+(digits[1]-'0');y=std::to_string(yy>=50?1900+yy:2000+yy);rest=digits.substr(2);}else if(t.tag==0x18&&digits.size()>=12){y=digits.substr(0,4);rest=digits.substr(4);}else return raw;if(rest.size()<10)return raw;auto frac=rest.size()>10?rest.substr(10):std::string();return y+"-"+rest.substr(0,2)+"-"+rest.substr(2,2)+"T"+rest.substr(4,2)+":"+rest.substr(6,2)+":"+rest.substr(8,2)+frac+"Z";}
void parse_certificate_extensions(std::span<const std::uint8_t>d,const std::vector<Der>&t,std::size_t first_optional,AuthenticodeCertificateInfo&out){
    for(std::size_t i=first_optional;i<t.size();++i){
        if(t[i].tag!=0xa3)continue;
        out.extensions_present=true;
        bool ok=false;auto wrap=children(d,t[i],ok);
        if(!ok||wrap.size()!=1||wrap[0].tag!=0x30)continue;
        auto exts=children(d,wrap[0],ok);if(!ok)continue;
        for(const auto&e:exts){
            if(e.tag!=0x30)continue;
            auto ev=children(d,e,ok);if(!ok||ev.size()<2||ev[0].tag!=0x06)continue;
            std::size_t z=1;bool critical=false;
            if(z<ev.size()&&ev[z].tag==0x01){critical=ev[z].length==1&&d[ev[z].content]!=0;++z;}
            if(z>=ev.size()||ev[z].tag!=0x04)continue;
            auto oid=oid_text(d,ev[0]);auto inner=d.subspan(ev[z].content,ev[z].length);
            if(oid=="2.5.29.37"){
                out.extended_key_usage_present=true;out.extended_key_usage_critical=critical;
                std::size_t p=0;Der seq;if(!der_one(inner,p,seq)||seq.tag!=0x30||p!=inner.size())continue;
                auto uses=children(inner,seq,ok);if(!ok)continue;
                for(const auto&u:uses){
                    auto x=oid_text(inner,u);if(x.empty())continue;
                    out.extended_key_usage_oids.push_back(x);
                    if(x=="1.3.6.1.5.5.7.3.3")out.eku_code_signing=true;
                    if(x=="1.3.6.1.5.5.7.3.8")out.eku_time_stamping=true;
                }
            }else if(oid=="2.5.29.19"){
                out.basic_constraints_present=true;
                std::size_t p=0;Der seq;if(!der_one(inner,p,seq)||seq.tag!=0x30||p!=inner.size())continue;
                auto bc=children(inner,seq,ok);
                if(ok&&!bc.empty()&&bc[0].tag==0x01&&bc[0].length==1)out.basic_constraints_ca=d[bc[0].content]!=0;
            }
        }
    }
    if(out.eku_code_signing&&out.eku_time_stamping)out.role_hint="CODE_SIGNING+TIME_STAMPING";
    else if(out.eku_code_signing)out.role_hint="CODE_SIGNING";
    else if(out.eku_time_stamping)out.role_hint="TIME_STAMPING";
    else if(out.extended_key_usage_present)out.role_hint="OTHER_EKU";
    else out.role_hint="EKU_NOT_PRESENT";
}

struct ParsedCert {AuthenticodeCertificateInfo info;Der issuer;};
struct ParsedSigner {AuthenticodeSignerInfo info;Der issuer;};
bool parse_pkcs7_identity(std::span<const std::uint8_t>der,std::vector<AuthenticodeCertificateInfo>&certs,std::vector<AuthenticodeSignerInfo>&signers,std::string&err);
bool parse_rfc3161_value(std::span<const std::uint8_t>d,const Der&value,AuthenticodeTimestampInfo&out);
std::string alg_name(std::span<const std::uint8_t>d,const Der&seq){bool ok=false;auto a=children(d,seq,ok);if(!ok||a.empty()||a[0].tag!=0x06)return{};auto o=oid_text(d,a[0]);if(o=="1.3.14.3.2.26")return"SHA1";if(o=="2.16.840.1.101.3.4.2.1")return"SHA256";if(o=="1.2.840.113549.1.1.1")return"RSA";if(o=="1.2.840.113549.1.1.5")return"SHA1-RSA";if(o=="1.2.840.113549.1.1.11")return"SHA256-RSA";if(o=="1.2.840.10045.4.3.2")return"ECDSA-SHA256";return o;}
void parse_attrs(std::span<const std::uint8_t>d,const Der&attrs,AuthenticodeSignerInfo&out,bool unauth){
    bool ok=false;auto vv=children(d,attrs,ok);if(!ok)return;for(const auto&a:vv){if(a.tag!=0x30)continue;auto av=children(d,a,ok);if(!ok||av.size()!=2||av[0].tag!=0x06||av[1].tag!=0x31)continue;auto oid=oid_text(d,av[0]);auto values=children(d,av[1],ok);if(!ok)continue;if(!unauth&&oid=="1.2.840.113549.1.9.5"&&!values.empty())out.signing_time=time_text(d,values[0]);if(unauth&&oid=="1.2.840.113549.1.9.6")out.countersignature_count+=static_cast<std::uint32_t>(values.size());if(unauth&&oid=="1.3.6.1.4.1.311.3.3.1"){out.rfc3161_timestamp_count+=static_cast<std::uint32_t>(values.size());for(const auto&v:values){AuthenticodeTimestampInfo ts;parse_rfc3161_value(d,v,ts);out.timestamps.push_back(std::move(ts));}}}
}
bool parse_pkcs7_identity(std::span<const std::uint8_t>der,std::vector<AuthenticodeCertificateInfo>&certs,std::vector<AuthenticodeSignerInfo>&signers,std::string&err){
    std::size_t p=0;Der root;if(!der_one(der,p,root)||root.tag!=0x30){err="PKCS#7 identity root invalid";return false;}bool ok=false;auto rc=children(der,root,ok);if(!ok||rc.size()<2||!oid_arr(der,rc[0],OID_SIGNED_DATA)||rc[1].tag!=0xa0){err="PKCS#7 identity ContentInfo invalid";return false;}auto cw=children(der,rc[1],ok);if(!ok||cw.size()!=1||cw[0].tag!=0x30){err="PKCS#7 identity SignedData wrapper invalid";return false;}auto sd=children(der,cw[0],ok);if(!ok||sd.size()<4||sd.back().tag!=0x31){err="PKCS#7 identity SignedData fields invalid";return false;}
    std::vector<ParsedCert> pc;for(std::size_t i=3;i+1<sd.size();++i){if(sd[i].tag!=0xa0)continue;auto cv=children(der,sd[i],ok);if(!ok){err="PKCS#7 certificate set malformed";return false;}for(const auto&c:cv){if(c.tag!=0x30)continue;auto cc=children(der,c,ok);if(!ok||cc.size()<3||cc[0].tag!=0x30)continue;auto t=children(der,cc[0],ok);if(!ok)continue;std::size_t z=0;if(!t.empty()&&t[0].tag==0xa0)++z;if(t.size()<z+6||t[z].tag!=0x02||t[z+2].tag!=0x30||t[z+3].tag!=0x30||t[z+4].tag!=0x30)continue;ParsedCert x;x.info.serial=integer_hex(der,t[z]);x.issuer=t[z+2];x.info.issuer=parse_name(der,t[z+2]);auto times=children(der,t[z+3],ok);if(ok&&times.size()>=2){x.info.not_before=time_text(der,times[0]);x.info.not_after=time_text(der,times[1]);}x.info.subject=parse_name(der,t[z+4]);parse_certificate_extensions(der,t,z+6,x.info);x.info.sha256_fingerprint=sha256_bytes(der.subspan(c.begin,c.end-c.begin));pc.push_back(std::move(x));}}
    auto sv=children(der,sd.back(),ok);if(!ok||sv.empty()){err="PKCS#7 SignerInfos malformed";return false;}std::vector<ParsedSigner> ps;for(const auto&si:sv){if(si.tag!=0x30)continue;auto sc=children(der,si,ok);if(!ok||sc.size()<5||sc[0].tag!=0x02)continue;ParsedSigner x;std::size_t z=1;if(sc[z].tag==0x30){auto sid=children(der,sc[z],ok);if(ok&&sid.size()==2&&sid[0].tag==0x30&&sid[1].tag==0x02){x.info.identifier_type="issuer_and_serial";x.issuer=sid[0];x.info.issuer=parse_name(der,sid[0]);x.info.serial=integer_hex(der,sid[1]);}}else if(sc[z].tag==0x80){x.info.identifier_type="subject_key_identifier";x.info.serial=hex_bytes(der.subspan(sc[z].content,sc[z].length));}++z;if(z>=sc.size()||sc[z].tag!=0x30)continue;x.info.digest_algorithm=alg_name(der,sc[z++]);if(z<sc.size()&&sc[z].tag==0xa0)parse_attrs(der,sc[z++],x.info,false);if(z>=sc.size()||sc[z].tag!=0x30)continue;x.info.signature_algorithm=alg_name(der,sc[z++]);if(z>=sc.size()||sc[z].tag!=0x04)continue;auto signature_value=der.subspan(sc[z].content,sc[z].length);x.info.signature_value_size=static_cast<std::uint32_t>(signature_value.size());x.info.signature_value_sha256=sha256_bytes(signature_value);++z;if(z<sc.size()&&sc[z].tag==0xa1)parse_attrs(der,sc[z],x.info,true);for(auto&t:x.info.timestamps){if(t.state=="FAILED"||t.message_imprint.empty())continue;std::string computed;if(t.message_imprint_algorithm=="SHA256")computed=sha256_bytes(signature_value);else if(t.message_imprint_algorithm=="SHA1")computed=hex20(sha1_bytes(signature_value));if(!computed.empty()){t.message_imprint_binding_checked=true;t.computed_signature_value_imprint=std::move(computed);t.message_imprint_matches_signature_value=t.computed_signature_value_imprint==t.message_imprint;if(!t.message_imprint_matches_signature_value&&t.error.empty())t.error="RFC3161 MessageImprint does not match the current SignerInfo signature value";}}ps.push_back(std::move(x));}
    for(auto&s:ps){if(s.info.identifier_type=="issuer_and_serial")for(std::size_t i=0;i<pc.size();++i)if(s.info.serial==pc[i].info.serial&&der_same(der,s.issuer,pc[i].issuer)){s.info.certificate_matched=true;s.info.certificate_index=static_cast<int>(i);pc[i].info.matched_primary_signer=true;break;}}
    for(auto&c:pc)certs.push_back(std::move(c.info));
    for(auto&s:ps)signers.push_back(std::move(s.info));
    if(signers.empty()){err="no structurally usable SignerInfo identity found";return false;}
    return true;
}
bool parse_rfc3161_value(std::span<const std::uint8_t>d,const Der&value,AuthenticodeTimestampInfo&out){
    out.kind="RFC3161";if(value.end<value.begin||value.end>d.size()){out.state="FAILED";out.error="RFC3161 attribute value range invalid";return false;}auto token=d.subspan(value.begin,value.end-value.begin);std::size_t p=0;Der root;if(!der_one(token,p,root)||root.tag!=0x30){out.state="FAILED";out.error="RFC3161 TimeStampToken ContentInfo invalid";return false;}bool ok=false;auto rc=children(token,root,ok);if(!ok||rc.size()<2||!oid_arr(token,rc[0],OID_SIGNED_DATA)||rc[1].tag!=0xa0){out.state="FAILED";out.error="RFC3161 token is not CMS SignedData";return false;}auto cw=children(token,rc[1],ok);if(!ok||cw.size()!=1||cw[0].tag!=0x30){out.state="FAILED";out.error="RFC3161 SignedData wrapper invalid";return false;}auto sd=children(token,cw[0],ok);if(!ok||sd.size()<4||sd[2].tag!=0x30){out.state="FAILED";out.error="RFC3161 SignedData fields invalid";return false;}auto ci=children(token,sd[2],ok);if(!ok||ci.size()<2||!oid_arr(token,ci[0],OID_TST_INFO)||ci[1].tag!=0xa0){out.state="FAILED";out.error="RFC3161 eContentType is not id-ct-TSTInfo";return false;}auto ew=children(token,ci[1],ok);if(!ok||ew.size()!=1||ew[0].tag!=0x04){out.state="FAILED";out.error="RFC3161 TSTInfo eContent is not an OCTET STRING";return false;}auto tst=token.subspan(ew[0].content,ew[0].length);std::size_t q=0;Der ti;if(!der_one(tst,q,ti)||ti.tag!=0x30||q!=tst.size()){out.state="FAILED";out.error="RFC3161 TSTInfo DER invalid";return false;}auto tv=children(tst,ti,ok);if(!ok||tv.size()<5||tv[0].tag!=0x02||tv[1].tag!=0x06||tv[2].tag!=0x30||tv[3].tag!=0x02||tv[4].tag!=0x18){out.state="FAILED";out.error="RFC3161 TSTInfo required fields invalid";return false;}out.policy=oid_text(tst,tv[1]);out.serial=integer_hex(tst,tv[3]);out.gen_time=time_text(tst,tv[4]);auto mi=children(tst,tv[2],ok);if(!ok||mi.size()!=2||mi[0].tag!=0x30||mi[1].tag!=0x04){out.state="FAILED";out.error="RFC3161 MessageImprint invalid";return false;}out.message_imprint_algorithm=alg_name(tst,mi[0]);if((out.message_imprint_algorithm=="SHA256"&&mi[1].length!=32)||(out.message_imprint_algorithm=="SHA1"&&mi[1].length!=20)){out.state="FAILED";out.error="RFC3161 MessageImprint length does not match the declared hash algorithm";return false;}out.message_imprint=hex_bytes(tst.subspan(mi[1].content,mi[1].length));
    std::vector<AuthenticodeCertificateInfo>certs;std::vector<AuthenticodeSignerInfo>signers;std::string metaerr;if(parse_pkcs7_identity(token,certs,signers,metaerr)){for(const auto&sg:signers)if(sg.certificate_matched&&sg.certificate_index>=0&&std::size_t(sg.certificate_index)<certs.size()){const auto&c=certs[std::size_t(sg.certificate_index)];out.signer_certificate_matched=true;out.signer_subject=c.subject;out.signer_issuer=c.issuer;out.signer_serial=c.serial;out.signer_certificate_sha256=c.sha256_fingerprint;out.signer_eku_time_stamping=c.eku_time_stamping;out.signer_extended_key_usage_critical=c.extended_key_usage_critical;out.signer_role_state=(c.eku_time_stamping&&c.extended_key_usage_critical)?"RFC3161_TIMESTAMP_EKU_CRITICAL":(c.eku_time_stamping?"TIMESTAMP_EKU_NONCRITICAL":"TIMESTAMP_EKU_NOT_PRESENT");break;}}else out.error=metaerr;
    out.state=out.signer_certificate_matched?"PARSED_SIGNER_MATCHED":"PARSED";return true;
}

struct EmbeddedPageHashEntry {std::uint32_t file_offset=0;std::vector<std::uint8_t>digest;};
struct EmbeddedPageHashes {bool present=false;std::string algorithm,error;std::vector<EmbeddedPageHashEntry>entries;};
void parse_embedded_page_hashes(std::span<const std::uint8_t>der,const Der&data_field,EmbeddedPageHashes&out){
    bool ok=false;auto data=children(der,data_field,ok);if(!ok||data.empty()||!oid_arr(der,data[0],OID_SPC_PE_IMAGE))return;
    if(data.size()<2||data[1].tag!=0x30)return;
    auto image=children(der,data[1],ok);if(!ok||image.empty()||image[0].tag!=0x03){out.error="SpcPeImageData structure invalid";return;}
    if(image.size()<2)return;
    if(image[1].tag!=0xa0){out.error="SpcPeImageData file link wrapper invalid";return;}
    auto file=children(der,image[1],ok);if(!ok||file.size()!=1||file[0].tag!=0xa1){out.error="SpcPeImageData page-hash moniker wrapper invalid";return;}
    auto moniker=children(der,file[0],ok);if(!ok||moniker.size()!=2||moniker[0].tag!=0x04||moniker[1].tag!=0x04){out.error="SpcSerializedObject page-hash moniker invalid";return;}
    auto classid=der.subspan(moniker[0].content,moniker[0].length);if(classid.size()!=PAGE_HASH_CLASSID.size()||!std::equal(PAGE_HASH_CLASSID.begin(),PAGE_HASH_CLASSID.end(),classid.begin()))return;
    out.present=true;auto serialized=der.subspan(moniker[1].content,moniker[1].length);std::size_t p=0;Der root;if(!der_one(serialized,p,root)||root.tag!=0x31||p!=serialized.size()){out.error="page-hash serializedData SET invalid";return;}auto set=children(serialized,root,ok);if(!ok||set.size()!=1||set[0].tag!=0x30){out.error="page-hash serializedData attribute invalid";return;}auto attr=children(serialized,set[0],ok);if(!ok||attr.size()!=2||attr[0].tag!=0x06||attr[1].tag!=0x31){out.error="page-hash attribute fields invalid";return;}
    std::size_t digest_len=0;if(oid_arr(serialized,attr[0],OID_PAGE_HASH_V1)){out.algorithm="SHA1";digest_len=20;}else if(oid_arr(serialized,attr[0],OID_PAGE_HASH_V2)){out.algorithm="SHA256";digest_len=32;}else{out.algorithm="UNSUPPORTED";out.error="unsupported Authenticode page-hash algorithm OID "+oid_text(serialized,attr[0]);return;}
    auto values=children(serialized,attr[1],ok);if(!ok||values.size()!=1||values[0].tag!=0x04){out.error="page-hash attribute value invalid";return;}auto blob=serialized.subspan(values[0].content,values[0].length);const auto step=std::size_t(4)+digest_len;if(blob.size()<step*2||blob.size()%step){out.error="page-hash record blob geometry invalid";return;}auto count=blob.size()/step;if(count>1000000){out.error="page-hash record count unreasonable";return;}out.entries.reserve(count);
    std::uint32_t previous=0;for(std::size_t i=0;i<count;++i){auto q=i*step;std::uint32_t off=std::uint32_t(blob[q])|(std::uint32_t(blob[q+1])<<8)|(std::uint32_t(blob[q+2])<<16)|(std::uint32_t(blob[q+3])<<24);if((i==0&&off!=0)||(i>0&&off<=previous)){out.error="page-hash file offsets are not strictly increasing from zero";out.entries.clear();return;}previous=off;EmbeddedPageHashEntry e;e.file_offset=off;e.digest.assign(blob.begin()+static_cast<std::ptrdiff_t>(q+4),blob.begin()+static_cast<std::ptrdiff_t>(q+step));out.entries.push_back(std::move(e));}
    if(!std::all_of(out.entries.back().digest.begin(),out.entries.back().digest.end(),[](std::uint8_t b){return b==0;})){out.error="page-hash terminator digest is not zero";out.entries.clear();return;}
}

bool parse_spc_digest(std::span<const std::uint8_t>der,std::string&alg,std::vector<std::uint8_t>&digest,std::uint32_t&signer_count,EmbeddedPageHashes&page_hashes,std::string&err){
    std::size_t p=0;Der root;if(!der_one(der,p,root)||root.tag!=0x30){err="PKCS#7 ContentInfo DER root invalid";return false;}for(;p<der.size();++p)if(der[p]!=0){err="non-zero bytes follow PKCS#7 DER root";return false;}
    bool ok=false;auto rc=children(der,root,ok);if(!ok||rc.size()<2||!oid_arr(der,rc[0],OID_SIGNED_DATA)||rc[1].tag!=0xa0){err="certificate is not PKCS#7 SignedData";return false;}
    auto c0=children(der,rc[1],ok);if(!ok||c0.size()!=1||c0[0].tag!=0x30){err="PKCS#7 SignedData wrapper invalid";return false;}
    auto sd=children(der,c0[0],ok);if(!ok||sd.size()<4||sd[0].tag!=0x02||sd[1].tag!=0x31||sd[2].tag!=0x30||sd.back().tag!=0x31){err="PKCS#7 SignedData fields invalid";return false;}
    auto signers=children(der,sd.back(),ok);if(!ok||signers.empty()){err="PKCS#7 SignerInfos is empty or malformed";return false;}for(const auto&x:signers)if(x.tag!=0x30){err="PKCS#7 SignerInfo entry is not a SEQUENCE";return false;}signer_count=static_cast<std::uint32_t>(signers.size());
    auto ci=children(der,sd[2],ok);if(!ok||ci.size()<2||!oid_arr(der,ci[0],OID_SPC_INDIRECT)||ci[1].tag!=0xa0){err="PKCS#7 content is not SpcIndirectDataContent";return false;}
    auto wrap=children(der,ci[1],ok);if(!ok||wrap.empty()){err="SpcIndirectDataContent wrapper empty";return false;}
    Der spc{};
    if(wrap.size()==1&&wrap[0].tag==0x30)spc=wrap[0];
    else if(wrap.size()==1&&wrap[0].tag==0x04){std::span<const std::uint8_t>inner=der.subspan(wrap[0].content,wrap[0].length);std::size_t q=0;if(!der_one(inner,q,spc)||spc.tag!=0x30||q!=inner.size()){err="encapsulated SpcIndirectDataContent invalid";return false;}spc.begin+=wrap[0].content;spc.content+=wrap[0].content;spc.end+=wrap[0].content;}
    else{err="SpcIndirectDataContent DER shape unsupported";return false;}
    auto sc=children(der,spc,ok);if(!ok||sc.size()!=2||sc[0].tag!=0x30||sc[1].tag!=0x30){err="SpcIndirectDataContent fields invalid";return false;}
    parse_embedded_page_hashes(der,sc[0],page_hashes);
    auto di=children(der,sc[1],ok);if(!ok||di.size()!=2||di[0].tag!=0x30||di[1].tag!=0x04){err="SpcIndirectDataContent DigestInfo invalid";return false;}
    auto ai=children(der,di[0],ok);if(!ok||ai.empty()||ai[0].tag!=0x06){err="Authenticode digest AlgorithmIdentifier invalid";return false;}
    if(oid_arr(der,ai[0],OID_SHA1))alg="SHA1";else if(oid_arr(der,ai[0],OID_SHA256))alg="SHA256";else alg="UNSUPPORTED";
    digest.assign(der.begin()+static_cast<std::ptrdiff_t>(di[1].content),der.begin()+static_cast<std::ptrdiff_t>(di[1].end));
    if((alg=="SHA1"&&digest.size()!=20)||(alg=="SHA256"&&digest.size()!=32)){err="Authenticode digest length does not match algorithm";return false;}
    return true;
}

struct PeHashLayout {std::size_t checksum=0,security_dir=0,headers=0;bool security_dir_available=false;std::uint64_t cert_off=0,cert_size=0,last_section_end=0;std::vector<std::pair<std::uint32_t,std::uint32_t>>sections;std::string error;};
std::optional<PeHashLayout> hash_layout(std::span<const std::uint8_t>d){
    PeHashLayout x;if(d.size()<0x40||d[0]!='M'||d[1]!='Z'){x.error="not PE";return x;}std::uint32_t pe=0;if(!rd(d,0x3c,pe)||std::uint64_t(pe)+24>d.size()||std::memcmp(d.data()+pe,"PE\0\0",4)){x.error="invalid PE header";return x;}
    std::uint16_t nsec=0,opt_size=0,magic=0;rd(d,pe+6,nsec);rd(d,pe+20,opt_size);auto opt=std::size_t(pe)+24;if(opt+opt_size>d.size()||!rd(d,opt,magic)||(magic!=0x10b&&magic!=0x20b)){x.error="invalid optional header";return x;}
    auto dd=opt+(magic==0x20b?112:96);std::uint32_t dirs=0;if(!rd(d,opt+(magic==0x20b?108:92),dirs)){x.error="PE NumberOfRvaAndSizes unavailable";return x;}
    x.checksum=opt+64;std::uint32_t hs=0;if(!rd(d,opt+60,hs)||!hs||hs>d.size()||x.checksum+4>hs){x.error="PE Authenticode header geometry invalid";return x;}x.headers=hs;
    if(dirs>4&&dd+5*8<=opt+opt_size){x.security_dir_available=true;x.security_dir=dd+4*8;if(x.security_dir+8>hs||x.checksum+4>x.security_dir){x.error="PE Certificate Table directory geometry invalid";return x;}std::uint32_t co=0,cs=0;rd(d,x.security_dir,co);rd(d,x.security_dir+4,cs);x.cert_off=co;x.cert_size=cs;}
    auto st=opt+opt_size;if(st+std::uint64_t(nsec)*40>d.size()){x.error="PE section table truncated";return x;}for(std::uint16_t i=0;i<nsec;++i){auto o=st+std::size_t(i)*40;std::uint32_t rs=0,ro=0;rd(d,o+16,rs);rd(d,o+20,ro);if(!rs)continue;if(ro<hs||std::uint64_t(ro)+rs>d.size()){x.error="PE section raw range invalid for Authenticode";return x;}x.sections.push_back({ro,rs});x.last_section_end=std::max<std::uint64_t>(x.last_section_end,std::uint64_t(ro)+rs);}
    std::sort(x.sections.begin(),x.sections.end());std::uint64_t prev=hs;for(auto [o,n]:x.sections){if(o<prev){x.error="PE section raw ranges overlap for Authenticode";return x;}prev=std::uint64_t(o)+n;}x.last_section_end=std::max<std::uint64_t>(x.last_section_end,hs);return x;
}
std::vector<std::span<const std::uint8_t>> covered_parts(std::span<const std::uint8_t>d,const PeHashLayout&x){std::vector<std::span<const std::uint8_t>>v;if(!x.security_dir_available)return v;v.push_back(d.subspan(0,x.checksum));v.push_back(d.subspan(x.checksum+4,x.security_dir-(x.checksum+4)));v.push_back(d.subspan(x.security_dir+8,x.headers-(x.security_dir+8)));for(auto[o,n]:x.sections)v.push_back(d.subspan(o,n));return v;}
std::string compute_digest(std::span<const std::uint8_t>d,const PeHashLayout&x,const std::string&alg){auto p=covered_parts(d,x);if(alg=="SHA256")return sha256_parts(p);if(alg=="SHA1")return hex20(sha1_parts(p));return{};}
std::string compute_parts_digest(const std::string&alg,const std::vector<std::span<const std::uint8_t>>&parts){if(alg=="SHA256")return sha256_parts(parts);if(alg=="SHA1")return hex20(sha1_parts(parts));return{};}
struct CurrentPageHashEntry {std::uint32_t file_offset=0,rva=0,file_bytes=0;std::string region,digest;bool terminator=false;};
bool recompute_page_hashes(std::span<const std::uint8_t>d,const PeInfo&pe,const PeHashLayout&x,const std::string&alg,std::uint32_t&page_size,std::vector<CurrentPageHashEntry>&out,std::string&err){
    if(alg!="SHA1"&&alg!="SHA256"){err="unsupported page-hash recomputation algorithm";return false;}
    std::uint32_t peoff=0;if(d.size()<0x40||!rd(d,0x3c,peoff)||std::uint64_t(peoff)+24>d.size()){err="PE header unavailable for page-hash recomputation";return false;}auto opt=std::size_t(peoff)+24;std::uint32_t section_alignment=0,file_alignment=0,headers=0;if(!rd(d,opt+32,section_alignment)||!rd(d,opt+36,file_alignment)||!rd(d,opt+60,headers)){err="PE alignment/header fields unavailable for page-hash recomputation";return false;}
    if(file_alignment<512||file_alignment>0xffff){err="PE FileAlignment is outside the supported page-hash range";return false;}if(section_alignment<file_alignment||section_alignment>4u*1024u*1024u){err="PE SectionAlignment is invalid/unreasonable for page hashes";return false;}if(headers!=x.headers||headers>section_alignment||x.security_dir+8>headers){err="PE header/page geometry invalid for page hashes";return false;}page_size=section_alignment;
    std::vector<std::uint8_t>zeros(page_size,0);std::vector<std::span<const std::uint8_t>>parts;parts.push_back(d.subspan(0,x.checksum));parts.push_back(d.subspan(x.checksum+4,x.security_dir-(x.checksum+4)));parts.push_back(d.subspan(x.security_dir+8,headers-(x.security_dir+8)));if(page_size>headers)parts.push_back(std::span<const std::uint8_t>(zeros).first(page_size-headers));auto hd=compute_parts_digest(alg,parts);if(hd.empty()){err="page-hash header digest computation failed";return false;}out.push_back({0,0,headers,"PE headers",std::move(hd),false});
    std::uint64_t previous_end=headers,last_end=0;for(const auto&sec:pe.sections){if(!sec.raw_size)continue;auto ro=std::uint64_t(sec.raw_offset),rs=std::uint64_t(sec.raw_size);if(ro<previous_end||ro+rs>d.size()||ro+rs>x.cert_off||ro+rs>0xffffffffull){err="PE section raw geometry is invalid for page hashes";out.clear();return false;}for(std::uint64_t l=0;l<rs;l+=page_size){auto n=static_cast<std::size_t>(std::min<std::uint64_t>(page_size,rs-l));parts.clear();parts.push_back(d.subspan(static_cast<std::size_t>(ro+l),n));if(n<page_size)parts.push_back(std::span<const std::uint8_t>(zeros).first(page_size-n));auto h=compute_parts_digest(alg,parts);if(h.empty()){err="page-hash section digest computation failed";out.clear();return false;}CurrentPageHashEntry e;e.file_offset=static_cast<std::uint32_t>(ro+l);e.rva=sec.rva+static_cast<std::uint32_t>(l);e.file_bytes=static_cast<std::uint32_t>(n);e.region=sec.name;e.digest=std::move(h);out.push_back(std::move(e));}last_end=ro+rs;previous_end=ro+rs;}
    if(!last_end||last_end>0xffffffffull){err="page-hash terminator offset unavailable";out.clear();return false;}CurrentPageHashEntry term;term.file_offset=static_cast<std::uint32_t>(last_end);term.region="terminator";term.digest=std::string((alg=="SHA256"?32u:20u)*2,'0');term.terminator=true;out.push_back(std::move(term));return true;
}
void verify_page_hashes(std::span<const std::uint8_t>d,const PeInfo&pe,const PeHashLayout&layout,const EmbeddedPageHashes&embedded,AuthenticodeSignatureInfo&out){
    out.page_hash_state="NOT_PRESENT";if(!embedded.present)return;out.page_hashes_present=true;out.page_hash_algorithm=embedded.algorithm;
    if(!embedded.error.empty()){out.page_hash_state=embedded.algorithm=="UNSUPPORTED"?"UNSUPPORTED_ALGORITHM":"PARSE_FAILED";out.page_hash_error=embedded.error;return;}
    std::vector<CurrentPageHashEntry>current;std::string err;if(!recompute_page_hashes(d,pe,layout,embedded.algorithm,out.page_size,current,err)){out.page_hash_state="RECOMPUTE_FAILED";out.page_hash_error=std::move(err);return;}out.page_hashes_verified=true;
    const auto count=std::max(embedded.entries.size(),current.size());out.page_hashes.reserve(count);for(std::size_t i=0;i<count;++i){AuthenticodePageHashEntry e;const bool hs=i<embedded.entries.size(),hc=i<current.size();if(hs){e.signed_file_offset=embedded.entries[i].file_offset;e.signed_digest=hex_bytes(embedded.entries[i].digest);}if(hc){e.current_file_offset=current[i].file_offset;e.current_rva=current[i].rva;e.current_file_bytes=current[i].file_bytes;e.region=current[i].region;e.computed_digest=current[i].digest;e.terminator=current[i].terminator;}else if(hs&&i+1==embedded.entries.size())e.terminator=std::all_of(embedded.entries[i].digest.begin(),embedded.entries[i].digest.end(),[](std::uint8_t b){return b==0;});e.offset_match=hs&&hc&&e.signed_file_offset==e.current_file_offset;e.digest_match=hs&&hc&&e.signed_digest==e.computed_digest;e.match=e.offset_match&&e.digest_match;if(!e.match)++out.page_hash_mismatch_count;out.page_hashes.push_back(std::move(e));}
    out.page_hash_state=out.page_hash_mismatch_count==0&&embedded.entries.size()==current.size()?"MATCH":"MISMATCH";
}
void parse_pkcs7_signature(std::span<const std::uint8_t>file,const PeInfo&pe,const PeHashLayout&layout,std::span<const std::uint8_t>blob,AuthenticodeSignatureInfo&out){
    out.pkcs7=true;std::string alg,err;std::vector<std::uint8_t>dig;std::uint32_t signer_count=0;EmbeddedPageHashes page_hashes;
    if(!parse_spc_digest(blob,alg,dig,signer_count,page_hashes,err)){out.state="PKCS7_PARSE_FAILED";out.error=std::move(err);return;}
    out.spc_indirect_data=true;out.signer_infos_present=true;out.signer_info_count=signer_count;out.digest_extracted=true;std::string metaerr;if(parse_pkcs7_identity(blob,out.certificates,out.signers,metaerr))out.signer_metadata_state="PARSED";else{out.signer_metadata_state="PARTIAL";out.signer_metadata_error=std::move(metaerr);}verify_page_hashes(file,pe,layout,page_hashes,out);out.digest_algorithm=alg;out.signed_digest=hex_bytes(dig);out.computed_digest=compute_digest(file,layout,alg);if(out.computed_digest.empty()){out.state="UNSUPPORTED_DIGEST";out.error="SpcIndirectDataContent digest algorithm is not yet supported for local recomputation";}else{out.digest_match=out.signed_digest==out.computed_digest;out.state=out.digest_match?"DIGEST_MATCH":"DIGEST_MISMATCH";}
}
bool collect_nested_signature_blobs(std::span<const std::uint8_t>der,std::vector<std::vector<std::uint8_t>>&out,std::string&err){
    std::size_t p=0;Der root;if(!der_one(der,p,root)||root.tag!=0x30){err="nested-signature scan: PKCS#7 ContentInfo invalid";return false;}bool ok=false;auto rc=children(der,root,ok);if(!ok||rc.size()<2||!oid_arr(der,rc[0],OID_SIGNED_DATA)||rc[1].tag!=0xa0)return true;auto cw=children(der,rc[1],ok);if(!ok||cw.size()!=1||cw[0].tag!=0x30){err="nested-signature scan: SignedData wrapper invalid";return false;}auto sd=children(der,cw[0],ok);if(!ok||sd.empty()||sd.back().tag!=0x31){err="nested-signature scan: SignerInfos invalid";return false;}auto signers=children(der,sd.back(),ok);if(!ok){err="nested-signature scan: SignerInfos set malformed";return false;}
    for(const auto&si:signers){if(si.tag!=0x30)continue;auto sc=children(der,si,ok);if(!ok)continue;for(const auto&field:sc){if(field.tag!=0xa1)continue;auto attrs=children(der,field,ok);if(!ok){err="nested-signature scan: unauthenticated attributes malformed";return false;}for(const auto&a:attrs){if(a.tag!=0x30)continue;auto av=children(der,a,ok);if(!ok||av.size()!=2||!oid_arr(der,av[0],OID_NESTED_SIGNATURE)||av[1].tag!=0x31)continue;auto values=children(der,av[1],ok);if(!ok){err="nested-signature attribute SET malformed";return false;}for(const auto&v:values){std::span<const std::uint8_t>blob;if(v.tag==0x30)blob=der.subspan(v.begin,v.end-v.begin);else if(v.tag==0x04)blob=der.subspan(v.content,v.length);else{err="nested-signature attribute value is not PKCS#7 ContentInfo/OCTET STRING";return false;}if(blob.empty()||blob.size()>16u*1024u*1024u){err="nested-signature PKCS#7 size invalid/unreasonable";return false;}out.emplace_back(blob.begin(),blob.end());if(out.size()>16){err="nested-signature count exceeds safety limit";return false;}}}}}
    return true;
}
}

AuthenticodeInfo analyze_authenticode(std::span<const std::uint8_t>d,const PeInfo&pe){
    AuthenticodeInfo out;if(!pe.valid)return out;auto lo=hash_layout(d);if(!lo){out.error="cannot derive Authenticode PE layout";out.state="FAILED";return out;}auto&x=*lo;if(!x.error.empty()){out.error=x.error;out.state="FAILED";return out;}
    out.checksum_offset=x.checksum;out.certificate_directory_entry_offset=x.security_dir;out.headers_size=x.headers;out.last_section_end=x.last_section_end;out.post_section_bytes=x.last_section_end<d.size()?d.size()-x.last_section_end:0;
    if(!x.security_dir_available||(!x.cert_off&&!x.cert_size)){out.state="NO_EMBEDDED_SIGNATURE";return out;}out.covered_bytes=x.headers-12;for(auto[o,n]:x.sections){(void)o;out.covered_bytes+=n;}out.present=true;out.certificate_table_offset=x.cert_off;out.certificate_table_size=x.cert_size;
    if(!x.cert_off||!x.cert_size||(x.cert_off&7)||x.cert_off<out.last_section_end||x.cert_off>d.size()||x.cert_size>d.size()-x.cert_off){out.error="PE Attribute Certificate Table range/alignment invalid";out.state="FAILED";return out;}
    out.pre_certificate_unhashed_bytes=x.cert_off>out.last_section_end?x.cert_off-out.last_section_end:0;auto cert_end=x.cert_off+x.cert_size;out.post_certificate_unhashed_bytes=cert_end<d.size()?d.size()-cert_end:0;
    struct PendingNested { std::vector<std::uint8_t> blob; int parent=-1; std::uint32_t depth=0; };
    std::vector<PendingNested> nested_queue;
    std::uint64_t q=x.cert_off,end=cert_end;while(q<end){if(q+8>end){out.error="WIN_CERTIFICATE header truncated";out.state="FAILED";return out;}std::uint32_t len=0;std::uint16_t rev=0,type=0;rd(d,q,len);rd(d,q+4,rev);rd(d,q+6,type);if(len<8||len>end-q){out.error="WIN_CERTIFICATE length invalid";out.state="FAILED";return out;}auto adv=(std::uint64_t(len)+7)&~std::uint64_t(7);if(adv>end-q){out.error="WIN_CERTIFICATE aligned length exceeds table";out.state="FAILED";return out;}for(std::uint64_t z=q+len;z<q+adv;++z)if(d[z]){out.error="WIN_CERTIFICATE alignment padding is non-zero";out.state="FAILED";return out;}
        AuthenticodeSignatureInfo s;s.certificate_offset=q;s.certificate_size=len;s.revision=rev;s.certificate_type=type;s.pkcs7=type==0x0002;
        auto blob=d.subspan(q+8,len-8);if(s.pkcs7){parse_pkcs7_signature(d,pe,x,blob,s);std::vector<std::vector<std::uint8_t>>nested;std::string nerr;if(!collect_nested_signature_blobs(blob,nested,nerr))s.nested_signature_error=std::move(nerr);s.nested_signature_count=static_cast<std::uint32_t>(nested.size());auto parent=static_cast<int>(out.signatures.size());for(auto&n:nested)nested_queue.push_back({std::move(n),parent,1});}else s.state="NON_PKCS7_CERTIFICATE";out.signatures.push_back(std::move(s));q+=adv;
    }
    if(q!=end){out.error="Attribute Certificate Table size does not equal aligned WIN_CERTIFICATE entries";out.state="FAILED";return out;}
    for(std::size_t qi=0;qi<nested_queue.size();++qi){if(out.signatures.size()>=16){if(nested_queue[qi].parent>=0&&std::size_t(nested_queue[qi].parent)<out.signatures.size())out.signatures[std::size_t(nested_queue[qi].parent)].nested_signature_error="nested-signature total count exceeds safety limit";break;}auto pending=std::move(nested_queue[qi]);AuthenticodeSignatureInfo ns;ns.source="SPC_NESTED_SIGNATURE";ns.nesting_depth=pending.depth;ns.parent_signature_index=pending.parent;ns.certificate_type=0x0002;ns.certificate_size=pending.blob.size();parse_pkcs7_signature(d,pe,x,pending.blob,ns);std::vector<std::vector<std::uint8_t>>children;std::string nerr;if(!collect_nested_signature_blobs(pending.blob,children,nerr))ns.nested_signature_error=std::move(nerr);ns.nested_signature_count=static_cast<std::uint32_t>(children.size());auto parent=static_cast<int>(out.signatures.size());if(!children.empty()){if(pending.depth>=4)ns.nested_signature_error="nested-signature depth exceeds safety limit";else for(auto&child:children)nested_queue.push_back({std::move(child),parent,pending.depth+1});}out.signatures.push_back(std::move(ns));}
    out.certificate_table_valid=true;
    bool match=false,mismatch=false,parsed=false,pkcs7_failed=false;for(const auto&s:out.signatures){parsed|=s.digest_extracted;match|=s.digest_extracted&&s.digest_match;mismatch|=s.digest_extracted&&!s.computed_digest.empty()&&!s.digest_match;pkcs7_failed|=s.pkcs7&&!s.digest_extracted;}
    if(mismatch)out.state="SIGNED_CONTENT_MISMATCH";else if(match)out.state="SIGNED_CONTENT_MATCH";else if(parsed)out.state="DIGEST_UNSUPPORTED";else if(pkcs7_failed)out.state="SIGNATURE_PARSE_FAILED";else out.state="CERTIFICATE_TABLE_PRESENT";return out;
}

Finding authenticode_finding(const AuthenticodeInfo&i){
    Finding f;f.kind="integrity";f.family="Authenticode";const bool failed=i.state=="FAILED"||i.state=="SIGNATURE_PARSE_FAILED"||i.state=="DIGEST_UNSUPPORTED";f.state=failed?"FAILED":"CONFIRMED";f.variant=i.state;
    if(i.present)f.evidence.push_back("PE Attribute Certificate Table is present at file offset 0x"+[] (std::uint64_t v){std::ostringstream o;o<<std::hex<<v;return o.str();}(i.certificate_table_offset));
    if(i.certificate_table_valid)f.evidence.push_back("WIN_CERTIFICATE table geometry and 8-byte alignment validated");
    for(const auto&s:i.signatures){for(const auto&sg:s.signers)if(sg.certificate_matched&&sg.certificate_index>=0&&std::size_t(sg.certificate_index)<s.certificates.size()){const auto&c=s.certificates[std::size_t(sg.certificate_index)];f.evidence.push_back("embedded Authenticode signer certificate matched by issuer+serial: "+c.subject);if(c.eku_code_signing)f.evidence.push_back("matched signer certificate Extended Key Usage includes id-kp-codeSigning");else if(c.extended_key_usage_present)f.negative_evidence.push_back("matched Authenticode signer certificate Extended Key Usage does not include id-kp-codeSigning");if(!sg.signing_time.empty())f.evidence.push_back("PKCS#9 signingTime="+sg.signing_time);if(sg.countersignature_count)f.evidence.push_back("traditional Authenticode countersignature attributes="+std::to_string(sg.countersignature_count));if(sg.rfc3161_timestamp_count)f.evidence.push_back("RFC3161 Authenticode timestamp-token attributes="+std::to_string(sg.rfc3161_timestamp_count));for(const auto&t:sg.timestamps){if(t.signer_certificate_matched&&t.signer_eku_time_stamping&&t.signer_extended_key_usage_critical)f.evidence.push_back("matched RFC3161 TSA certificate has critical id-kp-timeStamping Extended Key Usage");else if(t.signer_certificate_matched&&!t.signer_eku_time_stamping)f.negative_evidence.push_back("matched RFC3161 TSA certificate does not expose id-kp-timeStamping Extended Key Usage");else if(t.signer_certificate_matched&&t.signer_eku_time_stamping&&!t.signer_extended_key_usage_critical)f.negative_evidence.push_back("matched RFC3161 TSA certificate timeStamping Extended Key Usage is not critical");if(t.message_imprint_binding_checked&&t.message_imprint_matches_signature_value)f.evidence.push_back("RFC3161 MessageImprint matches the declared hash of the current SignerInfo signature value");else if(t.message_imprint_binding_checked&&!t.message_imprint_matches_signature_value)f.negative_evidence.push_back("RFC3161 MessageImprint does not bind to the current SignerInfo signature value");if(!t.error.empty()&&!t.message_imprint_binding_checked)f.negative_evidence.push_back("RFC3161 timestamp metadata validation: "+t.error);}}if(!s.signer_metadata_error.empty())f.negative_evidence.push_back(s.signer_metadata_error);if(s.page_hashes_present){f.fields["page_hash_state"]=s.page_hash_state;f.fields["page_hash_algorithm"]=s.page_hash_algorithm;f.fields["page_hash_entries"]=std::to_string(s.page_hashes.size());f.fields["page_hash_mismatch_count"]=std::to_string(s.page_hash_mismatch_count);f.fields["page_hash_size"]=std::to_string(s.page_size);if(s.page_hash_state=="MATCH")f.evidence.push_back(s.page_hash_algorithm+" Authenticode PE page hashes match all "+std::to_string(s.page_hashes.size())+" signed page records");else if(s.page_hash_state=="MISMATCH")f.negative_evidence.push_back("Authenticode PE page hashes mismatch on "+std::to_string(s.page_hash_mismatch_count)+" record(s)");else if(!s.page_hash_error.empty())f.negative_evidence.push_back("Authenticode page-hash validation: "+s.page_hash_error);for(const auto&ph:s.page_hashes){if(ph.match||ph.terminator||!ph.current_file_bytes)continue;std::ostringstream label;label<<"Authenticode page-hash mismatch: "<<ph.region<<" RVA 0x"<<std::hex<<ph.current_rva;f.ranges.push_back({ph.current_file_offset,ph.current_file_bytes,label.str()});}}if(s.digest_extracted){f.evidence.push_back(s.digest_algorithm+" signed PE image digest="+s.signed_digest);if(!s.computed_digest.empty())f.evidence.push_back(s.digest_algorithm+" recomputed Authenticode PE image digest="+s.computed_digest);if(s.state=="DIGEST_MISMATCH")f.negative_evidence.push_back("signed PE image digest does not match the current Authenticode-covered bytes");if(s.state=="UNSUPPORTED_DIGEST")f.negative_evidence.push_back(s.error);}else if(!s.error.empty())f.negative_evidence.push_back(s.error);}
    if(!i.error.empty())f.negative_evidence.push_back(i.error);
    if(i.checksum_offset)f.ranges.push_back({i.checksum_offset,4,"Authenticode-excluded PE CheckSum"});
    if(i.certificate_directory_entry_offset)f.ranges.push_back({i.certificate_directory_entry_offset,8,"Authenticode-excluded Certificate Table directory entry"});
    if(i.certificate_table_size)f.ranges.push_back({i.certificate_table_offset,i.certificate_table_size,"Authenticode-excluded Attribute Certificate Table"});
    if(i.pre_certificate_unhashed_bytes)f.ranges.push_back({i.last_section_end,i.pre_certificate_unhashed_bytes,"post-section bytes not covered by PE image hash"});
    if(i.post_certificate_unhashed_bytes)f.ranges.push_back({i.certificate_table_offset+i.certificate_table_size,i.post_certificate_unhashed_bytes,"post-certificate bytes not covered by PE image hash"});
    f.fields["integrity_state"]=i.state;f.fields["image_hash_excludes_checksum"]="true";f.fields["image_hash_excludes_certificate_table"]="true";f.fields["image_hash_excludes_post_section_bytes"]="true";f.fields["certificate_table_offset"]=std::to_string(i.certificate_table_offset);f.fields["certificate_table_size"]=std::to_string(i.certificate_table_size);f.fields["covered_bytes"]=std::to_string(i.covered_bytes);f.fields["checksum_excluded_offset"]=std::to_string(i.checksum_offset);f.fields["certificate_directory_excluded_offset"]=std::to_string(i.certificate_directory_entry_offset);f.fields["post_section_unhashed_bytes"]=std::to_string(i.post_section_bytes);f.fields["pre_certificate_unhashed_bytes"]=std::to_string(i.pre_certificate_unhashed_bytes);f.fields["post_certificate_unhashed_bytes"]=std::to_string(i.post_certificate_unhashed_bytes);f.fields["cryptographic_signer_verification"]="NOT_PERFORMED_STATIC_DIGEST_LAYER";f.fields["catalog_signature_verification"]="NOT_CHECKED";
    if(i.state=="SIGNED_CONTENT_MISMATCH")f.suggested_actions.push_back("treat the mismatch as strong evidence that Authenticode-covered PE content or the embedded signature material was modified/corrupted; inspect changed executable/data sections first");
    if(i.state=="SIGNED_CONTENT_MATCH")f.suggested_actions.push_back("do not equate digest match with whole-file pristine: inspect Authenticode-excluded checksum/certificate metadata and post-section bytes separately");
    return f;
}
}
