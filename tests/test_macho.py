#!/usr/bin/env python3
import hashlib,json,pathlib,struct,subprocess,sys,tempfile
AR=pathlib.Path(sys.argv[1])
LC_SYMTAB=0x2;LC_MAIN=0x80000028;LC_SEGMENT_64=0x19;LC_LOAD_DYLIB=0xc;LC_UUID=0x1b;LC_CODE_SIGNATURE=0x1d;LC_ENCRYPTION_INFO_64=0x2c;LC_BUILD_VERSION=0x32;LC_ROUTINES_64=0x1a;LC_FUNCTION_STARTS=0x26

def pad_name(s):
    b=s.encode();return b+b'\0'*(16-len(b))
def dylib_cmd(name,endian='<'):
    n=name.encode()+b'\0';size=(24+len(n)+7)//8*8
    return struct.pack(endian+'IIIIII',LC_LOAD_DYLIB,size,24,0,0x10000,0x10000)+n+b'\0'*(size-24-len(n))
def section64(sect,seg,addr,size,off,flags):
    return struct.pack('<16s16sQQIIIIIIII',pad_name(sect),pad_name(seg),addr,size,off,3,0,0,flags,0,0,0)
def thin64(cpu=0x01000007,sub=3,dylib='/usr/lib/libSystem.B.dylib'):
    vm=0x100000000
    secs=[
      section64('__text','__TEXT',vm+0x400,16,0x400,0x80000400),
      section64('__mod_init_func','__DATA',vm+0x420,8,0x420,0x9),
      section64('__mod_term_func','__DATA',vm+0x428,8,0x428,0xa),
      section64('__thread_init','__DATA',vm+0x430,8,0x430,0x15),
    ]
    seg=struct.pack('<II16sQQQQiiII',LC_SEGMENT_64,72+80*len(secs),pad_name('__TEXT'),vm,0x1000,0,0x600,7,5,len(secs),0)+b''.join(secs)
    main=struct.pack('<IIQQ',LC_MAIN,24,0x400,0) # intentionally before LC_SEGMENT_64
    dy=dylib_cmd(dylib)
    uuid=struct.pack('<II16s',LC_UUID,24,bytes(range(16)))
    build=struct.pack('<IIIIII',LC_BUILD_VERSION,24,1,(13<<16)|(2<<8)|1,14<<16,0)
    enc=struct.pack('<IIIIII',LC_ENCRYPTION_INFO_64,24,0x400,16,1,0)
    cs=struct.pack('<IIII',LC_CODE_SIGNATURE,16,0x580,16)
    routines=struct.pack('<IIQQQQQQQQ',LC_ROUTINES_64,72,vm+0x470,0,0,0,0,0,0,0)
    strings=b'\0_alpha\0_beta\0_undef\0_alias\0'
    def sx(name): return strings.index(name.encode())
    syms=b''.join([
      struct.pack('<IBBHQ',sx('_alpha'),0x0f,1,0,vm+0x400),
      struct.pack('<IBBHQ',sx('_beta'),0x0f,1,0,vm+0x408),
      struct.pack('<IBBHQ',sx('_undef'),0x01,0,0,0),
      struct.pack('<IBBHQ',sx('_alias'),0x1e,1,0,vm+0x400),
    ])
    symtab=struct.pack('<IIIIII',LC_SYMTAB,24,0x500,4,0x550,len(strings))
    fnstarts=struct.pack('<IIII',LC_FUNCTION_STARTS,16,0x540,4)
    cmds=[main,seg,dy,uuid,build,enc,cs,routines,symtab,fnstarts]
    hdr=struct.pack('<IiiIIIII',0xfeedfacf,cpu,sub,2,len(cmds),sum(map(len,cmds)),0x200000,0)
    out=bytearray(0x600);out[:len(hdr)+sum(map(len,cmds))]=hdr+b''.join(cmds)
    out[0x400:0x410]=bytes(range(16));struct.pack_into('<Q',out,0x420,vm+0x450);struct.pack_into('<Q',out,0x428,vm+0x460);struct.pack_into('<Q',out,0x430,vm+0x480)
    out[0x500:0x500+len(syms)]=syms;out[0x540:0x544]=bytes([0x80,0x08,0x08,0x00]);out[0x550:0x550+len(strings)]=strings;out[0x580:0x590]=b'CODESIGNATURE!!!'
    return bytes(out)
def sec32_be(sect,seg,addr,size,off,flags):return struct.pack('>16s16sIIIIIIIII',pad_name(sect),pad_name(seg),addr,size,off,2,0,0,flags,0,0)
def thin32be():
    vm=0x1000;secs=[sec32_be('__text','__TEXT',vm+0x300,16,0x300,0x80000400),sec32_be('__mod_init_func','__DATA',vm+0x320,4,0x320,0x9)]
    main=struct.pack('>IIQQ',LC_MAIN,24,0x300,0)
    seg=struct.pack('>II16sIIIIiiII',1,56+68*len(secs),pad_name('__TEXT'),vm,0x1000,0,0x400,7,5,len(secs),0)+b''.join(secs)
    routine=struct.pack('>IIIIIIIIII',0x11,40,vm+0x350,0,0,0,0,0,0,0)
    minver=struct.pack('>IIII',0x24,16,10<<16|(15<<8)|7,11<<16)
    cmds=[main,seg,routine,minver]
    hdr=struct.pack('>IiiIIII',0xfeedface,18,0,2,len(cmds),sum(map(len,cmds)),0)
    out=bytearray(0x400);out[:len(hdr)+sum(map(len,cmds))]=hdr+b''.join(cmds);out[0x300:0x310]=b'PPC32-BIG-END!!!';struct.pack_into('>I',out,0x320,vm+0x330);return bytes(out)
def fat(slices,use64=False,cpu_override=None,overlap=False):
    magic=0xcafebabf if use64 else 0xcafebabe;entry=32 if use64 else 20
    offs=[0x1000,0x2000]
    if overlap:offs[1]=0x1100
    out=bytearray(max(offs[i]+len(s) for i,s in enumerate(slices)))
    struct.pack_into('>II',out,0,magic,len(slices))
    for i,(off,s) in enumerate(zip(offs,slices)):
        cpu,sub=struct.unpack_from('<ii',s,4)
        if cpu_override is not None and i==0:cpu=cpu_override
        if use64:struct.pack_into('>iiQQII',out,8+i*entry,cpu,sub,off,len(s),12,0)
        else:struct.pack_into('>iiIII',out,8+i*entry,cpu,sub,off,len(s),12)
        out[off:off+len(s)]=s
    return bytes(out)

def signed32(x):return x if x<0x80000000 else x-0x100000000
def segment64(name,vm,fileoff,filesize,sections,vmsize=0x2000):
    return struct.pack('<II16sQQQQiiII',LC_SEGMENT_64,72+80*len(sections),pad_name(name),vm,vmsize,fileoff,filesize,7,5,len(sections),0)+b''.join(sections)
def put_rel(out,field,target):struct.pack_into('<i',out,field,target-field)
def swift64(mode='valid',unknown=False):
    vm=0x100000000
    types_size=8 if mode in ('duplicate','zero_field_sibling','partial_sibling') else 4
    text_sections=[
      section64('__swift5_types','__TEXT',vm+0x800,types_size,0x800,0),
      section64('__swift5_fieldmd','__TEXT',vm+0x900,28,0x900,0),
      section64('__swift5_reflstr','__TEXT',vm+0xa00,0x100,0xa00,0),
      section64('__const','__TEXT',vm+0xb00,0x100,0xb00,0),
      section64('__text','__TEXT',vm+0xc00,16,0xc00,0x80000400),
    ]
    llvm_sections=[section64('__bundle','__LLVM',vm+0x2000,8,0x1200,0)]
    text=segment64('__TEXT',vm,0,0x1200,text_sections)
    llvm=segment64('__LLVM',vm+0x2000,0x1200,0x40,llvm_sections)
    build=struct.pack('<IIIIII',LC_BUILD_VERSION,24,2,17<<16,18<<16,0)
    cs=struct.pack('<IIII',LC_CODE_SIGNATURE,16,0x1240,16)
    cmds=[text,llvm,build,cs]
    if mode=='encrypted':cmds.append(struct.pack('<IIIIII',LC_ENCRYPTION_INFO_64,24,0x900,0x100,1,0))
    if unknown:cmds.append(struct.pack('<II',0x12345678,8))
    subtype=signed32(0x85000002)
    hdr=struct.pack('<IiiIIIII',0xfeedfacf,0x0100000c,subtype,2,len(cmds),sum(map(len,cmds)),0x200000,0)
    out=bytearray(0x1300);out[:len(hdr)+sum(map(len,cmds))]=hdr+b''.join(cmds)
    strings={}
    cursor=0xa00
    for name,value in [('module',b'TestMod\0'),('type',b'Widget\0'),('descriptor',b'$s7TestMod6WidgetV\0'),('field_type',b'Si\0'),('field',b'value\0')]:
        strings[name]=cursor;out[cursor:cursor+len(value)]=value;cursor+=len(value)
    struct.pack_into('<II',out,0xb00,0,0);put_rel(out,0xb08,strings['module'])
    struct.pack_into('<I',out,0xb20,17);put_rel(out,0xb24,0xb00);put_rel(out,0xb28,strings['type']);struct.pack_into('<I',out,0xb2c,0);put_rel(out,0xb30,0x900)
    put_rel(out,0x800,0xb20)
    if mode=='duplicate':put_rel(out,0x804,0xb20)
    elif mode=='zero_field_sibling':
        put_rel(out,0x804,0xb50)
        struct.pack_into('<II',out,0xb70,0,0);put_rel(out,0xb78,strings['module'])
        struct.pack_into('<I',out,0xb50,17);put_rel(out,0xb54,0xb70)
        put_rel(out,0xb58,strings['type']);struct.pack_into('<I',out,0xb5c,0)
        struct.pack_into('<I',out,0xb60,0)
    elif mode=='partial_sibling':
        raw=((0xb20-0x804)&0xffffffff)|1;struct.pack_into('<I',out,0x804,raw)
    put_rel(out,0x900,strings['descriptor']);struct.pack_into('<IHHI',out,0x904,0,0,12,1)
    struct.pack_into('<I',out,0x910,2);put_rel(out,0x914,strings['field_type']);put_rel(out,0x918,strings['field'])
    out[0xc00:0xc10]=bytes(range(16));out[0x1200:0x1208]=b'BITCODE!';out[0x1240:0x1250]=b'CODESIGNATURE!!!'
    if mode=='cycle':put_rel(out,0xb24,0xb20)
    elif mode=='oob':struct.pack_into('<i',out,0x800,0x70000000)
    elif mode=='bad_stride':struct.pack_into('<H',out,0x90a,8)
    elif mode=='bad_count':struct.pack_into('<I',out,0x90c,0xffffffff)
    elif mode=='kind_mismatch':struct.pack_into('<H',out,0x908,1)
    elif mode=='unterminated':put_rel(out,0x918,0xaf0);out[0xaf0:0xb00]=b'A'*16
    elif mode=='mangled_empty':put_rel(out,0x900,0xaf0)
    elif mode=='mangled_oob':struct.pack_into('<i',out,0x900,0x70000000)
    elif mode=='symbolic_absent':
        symbolic=b'\x01\x00\x00\x00\x00\x17\x00\x00\x00\x00Si'
        put_rel(out,0x900,0xad0);out[0xad0:0xad0+len(symbolic)+1]=symbolic+b'\0'
        struct.pack_into('<I',out,0x914,0)
    elif mode=='symbolic_pointer':
        symbolic=b'\x18'+b'\0'*8+b'\x1f'+b'\0'*8+b'Si'
        put_rel(out,0x900,0xad0);out[0xad0:0xad0+len(symbolic)+1]=symbolic+b'\0'
    elif mode=='mangled_absent':
        struct.pack_into('<I',out,0x900,0)
        struct.pack_into('<I',out,0x914,0)
    elif mode=='symbolic_truncated':
        put_rel(out,0x900,0xafc);out[0xafc:0xb00]=b'\x01\x01\x02\x03'
    elif mode=='symbolic_pointer_truncated':
        put_rel(out,0x900,0xaf8);out[0xaf8:0xb00]=b'\x18'+b'\x01'*7
    elif mode=='invalid_utf8':put_rel(out,0x918,0xaf0);out[0xaf0:0xaf2]=b'\xff\0'
    elif mode=='indirect_parent':
        raw=((0xb00-0xb24)&0xffffffff)|1;struct.pack_into('<I',out,0xb24,raw)
    return bytes(out)
def many_load_commands():
    commands=[struct.pack('<II',0xa,8) for _ in range(4097)]+[struct.pack('<II',0x12345678,8)]
    header=struct.pack('<IiiIIIII',0xfeedfacf,0x01000007,3,2,len(commands),sum(map(len,commands)),0,0)
    return header+b''.join(commands)
def swift_type_budget():
    vm=0x100000000
    sections=[
      section64('__swift5_types','__TEXT',vm+0x300,4*4097,0x300,0),
      section64('__swift5_fieldmd','__TEXT',vm+0x4400,16,0x4400,0),
      section64('__swift5_reflstr','__TEXT',vm+0x4500,0x100,0x4500,0),
    ]
    seg=segment64('__TEXT',vm,0,0x4600,sections,0x5000)
    hdr=struct.pack('<IiiIIIII',0xfeedfacf,0x0100000c,0,2,1,len(seg),0,0)
    out=bytearray(0x4600);out[:len(hdr)+len(seg)]=hdr+seg
    put_rel(out,0x4400,0x4500);out[0x4500:0x4504]=b'$s0\0'
    struct.pack_into('<IHHI',out,0x4404,0,0,12,0)
    return bytes(out)

def check_swift_structured(j):
    assert j['format']['kind']=='Mach-O' and j['format']['slice_policy']=='REPORT_ALL_DECLARED_SLICES_NO_SELECTION' and j['format']['selected_slice']==-1
    m=j['macho_slices'][0];assert m['architecture']=='arm64e' and m['arm64e'] and m['cpu_subtype_base']==2
    assert m['ptrauth_versioned'] and not m['ptrauth_kernel'] and m['ptrauth_abi_version']==5 and m['architecture_claim_scope']=='REPORT_ONLY_NO_SLICE_SELECTION'
    assert m['bitcode_state']=='BITCODE_PRESENT' and m['code_signature_state']=='PRESENT_UNVERIFIED' and m['code_signature_verification']=='NOT_PERFORMED'
    s=m['swift'];assert s['state']=='SWIFT_STRUCTURED' and s['evidence_level']=='SWIFT_STRUCTURED' and s['structured'] and s['source_or_semantic_recovery']=='UNSUPPORTED'
    assert s['complete_type_closures']==1
    assert s['record_outcomes']=={'type_records_skipped':0,'type_records_partial':0,'type_records_unsupported':0,'field_descriptors_skipped':0,'field_descriptors_partial':0,'field_records_skipped':0,'field_records_partial':0,'mangled_type_names_absent':1,'mangled_type_names_symbolic':0}
    assert [(x['module'],x['name'],x['kind'],x['mangled_type_name']) for x in s['types']]==[('TestMod','Widget','struct','$s7TestMod6WidgetV')]
    assert [(x['name'],x['mangled_type_name']) for x in s['types'][0]['fields']]==[('value','Si')]
    ty=s['types'][0];field=ty['fields'][0]
    assert ty['mangled_type_present'] and ty['mangled_type_plain_text'] and ty['mangled_type_byte_length']==len(b'$s7TestMod6WidgetV') and ty['mangled_type_symbolic_references']==0
    assert ty['mangled_type_sha256']==hashlib.sha256(b'$s7TestMod6WidgetV').hexdigest()
    assert field['mangled_type_present'] and field['mangled_type_plain_text'] and field['mangled_type_byte_length']==2 and field['mangled_type_symbolic_references']==0
    assert field['mangled_type_sha256']==hashlib.sha256(b'Si').hexdigest()
def analyze(p):
    cp=subprocess.run([str(AR),str(p),'--json'],check=True,stdout=subprocess.PIPE,text=True);return json.loads(cp.stdout)

def check_thin64(j):
    f=j['format'];assert f['kind']=='Mach-O' and f['fat'] is False and f['bits']==64 and f['machine']=='x86_64' and f['type']=='EXECUTE' and f['entry']==0x100000400
    assert f['file_offset_scope']=='current_input_file' and j['artifact']['offset_space']=='current_input_file' and j['artifact']['offset_basis']==j['input'] and j['artifact']['root_input']==j['input']
    assert len(j['macho_slices'])==1;m=j['macho_slices'][0]
    assert m['entry_file_offset']==0x400 and m['entry_va']==0x100000400
    assert m['uuid']=='00010203-0405-0607-0809-0a0b0c0d0e0f'
    assert m['platform']=='macOS' and m['min_os']=='13.2.1' and m['sdk']=='14.0.0'
    assert m['encrypted'] and m['cryptid']==1 and m['crypt_offset']==0x400 and m['crypt_size']==16
    assert m['code_signature'] and m['code_signature_offset']==0x580 and m['code_signature_size']==16
    assert m['dylibs']==['/usr/lib/libSystem.B.dylib']
    assert m['symbol_count']==4 and m['function_start_count']==2
    sy={x['name']:x for x in m['symbols']};assert sy['_alpha']['defined'] and sy['_alpha']['external'] and sy['_alpha']['value']==0x100000400 and sy['_alpha']['file_offset']==0x400;assert not sy['_undef']['defined'] and sy['_undef']['external'] and sy['_undef']['file_offset']==0;assert sy['_alias']['private_external'] and not sy['_alias']['external']
    fs=m['function_starts'];assert [(x['address'],x['file_offset'],x['symbol']) for x in fs]==[(0x100000400,0x400,'_alpha'),(0x100000408,0x408,'_beta')]
    names={(x['segment'],x['name']) for x in j['sections']};assert ('__TEXT','__text') in names and ('__DATA','__mod_init_func') in names
    pe=j['pre_entry']['slices'][0];assert pe['init_functions']==[0x100000450];assert pe['term_functions']==[0x100000460];assert pe['thread_init_functions']==[0x100000480];assert pe['routine_init_address']==0x100000470

def main():
  with tempfile.TemporaryDirectory(prefix='auto-refirst-macho-') as td:
    td=pathlib.Path(td);x86=thin64();arm=thin64(0x0100000c,0)
    p=td/'thin64';p.write_bytes(x86);j=analyze(p);check_thin64(j)
    # Text rendering should expose the same factual entry/pre-entry metadata.
    t=subprocess.run([str(AR),str(p)],check=True,stdout=subprocess.PIPE,text=True).stdout;assert 'Format: Mach-O' in t and 'LC_ROUTINES init=0x100000470' in t and '/usr/lib/libSystem.B.dylib' in t and 'Function starts: 2' in t and '_alpha' in t
    p=td/'ppc32be';p.write_bytes(thin32be());j=analyze(p);assert j['format']['kind']=='Mach-O' and j['format']['bits']==32 and j['format']['machine']=='PowerPC' and j['macho_slices'][0]['little_endian'] is False and j['format']['entry']==0x1300;assert j['pre_entry']['slices'][0]['init_functions']==[0x1330] and j['pre_entry']['slices'][0]['routine_init_address']==0x1350
    for use64 in (False,True):
      p=td/('fat64' if use64 else 'fat');p.write_bytes(fat([x86,arm],use64));j=analyze(p);assert j['format']['kind']=='Mach-O' and j['format']['fat'] and j['format']['fat64']==use64 and j['format']['slice_count']==2;assert [x['machine'] for x in j['macho_slices']]==['x86_64','arm64'];assert j['macho_slices'][0]['slice_offset']==0x1000 and j['macho_slices'][1]['slice_offset']==0x2000;assert any(x['slice']==1 and x['offset']>=0x2000 for x in j['sections']);assert j['macho_slices'][0]['symbols'][0]['file_offset']==0x1400 and j['macho_slices'][1]['symbols'][0]['file_offset']==0x2400;assert j['macho_slices'][0]['function_starts'][0]['file_offset']==0x1400 and j['macho_slices'][1]['function_starts'][0]['file_offset']==0x2400
    # Magic/header bait, CPU disagreement and overlapping universal slices must not confirm Mach-O.
    p=td/'truncated';p.write_bytes(b'\xcf\xfa\xed\xfe'+b'\0'*8);assert analyze(p)['format']['kind']=='unknown'
    p=td/'badcpu';p.write_bytes(fat([x86,arm],False,cpu_override=0x0100000c));assert analyze(p)['format']['kind']=='unknown'
    p=td/'overlap';p.write_bytes(fat([x86,arm],False,overlap=True));assert analyze(p)['format']['kind']=='unknown'
    d=bytearray(x86);struct.pack_into('<I',d,0x500,0xffffffff);p=td/'bad-strx';p.write_bytes(d);assert analyze(p)['format']['kind']=='unknown'
    d=bytearray(x86);d[0x505]=99;p=td/'bad-sect';p.write_bytes(d);assert analyze(p)['format']['kind']=='unknown'
    d=bytearray(x86);d[0x540:0x544]=b'\x80\x80\x80\x80';p=td/'bad-uleb';p.write_bytes(d);assert analyze(p)['format']['kind']=='unknown'
    d=bytearray(x86);d[0x540:0x544]=b'\x80\x0e\x00\x00';p=td/'bad-function-range';p.write_bytes(d);assert analyze(p)['format']['kind']=='unknown'
    # A complete synthetic relationship closure exercises the STRUCTURED state
    # machine, but is not real-public Swift evidence.
    p=td/'swift-structured';p.write_bytes(swift64());j=analyze(p);check_swift_structured(j)
    t=subprocess.run([str(AR),str(p)],check=True,stdout=subprocess.PIPE,text=True).stdout
    assert 'Architecture: arm64e' in t and 'Bitcode: BITCODE_PRESENT' in t
    assert 'Code signature state: PRESENT_UNVERIFIED' in t
    assert 'Swift metadata: SWIFT_STRUCTURED' in t and 'source_or_semantic_recovery=UNSUPPORTED' in t
    # Symbolic references are framed according to the Swift ABI and retained as
    # byte facts; they are never forced into UTF-8 or claimed as decoded types.
    p=td/'swift-symbolic-absent';p.write_bytes(swift64('symbolic_absent'));j=analyze(p);s=j['macho_slices'][0]['swift']
    assert s['state']=='SWIFT_STRUCTURED' and s['structured'] and s['complete_type_closures']==1
    ty=s['types'][0];field=ty['fields'][0];symbolic=b'\x01\x00\x00\x00\x00\x17\x00\x00\x00\x00Si'
    assert ty['mangled_type_name']=='' and ty['mangled_type_present'] and not ty['mangled_type_plain_text']
    assert ty['mangled_type_byte_length']==len(symbolic) and ty['mangled_type_symbolic_references']==2
    assert ty['mangled_type_sha256']==hashlib.sha256(symbolic).hexdigest()
    assert field['mangled_type_name']=='' and not field['mangled_type_present'] and not field['mangled_type_plain_text']
    assert field['mangled_type_byte_length']==0 and field['mangled_type_sha256']==''
    assert s['record_outcomes']['mangled_type_names_absent']==2 and s['record_outcomes']['mangled_type_names_symbolic']==1
    p=td/'swift-symbolic-pointer';p.write_bytes(swift64('symbolic_pointer'));j=analyze(p);s=j['macho_slices'][0]['swift']
    assert s['state']=='SWIFT_STRUCTURED' and s['coverage_state']=='STRUCTURED' and s['complete_type_closures']==1
    ty=s['types'][0];symbolic=b'\x18'+b'\0'*8+b'\x1f'+b'\0'*8+b'Si'
    assert ty['mangled_type_name']=='' and ty['mangled_type_present'] and not ty['mangled_type_plain_text']
    assert ty['mangled_type_byte_length']==len(symbolic) and ty['mangled_type_symbolic_references']==2
    assert ty['mangled_type_sha256']==hashlib.sha256(symbolic).hexdigest()
    assert s['record_outcomes']['mangled_type_names_absent']==1 and s['record_outcomes']['mangled_type_names_symbolic']==1
    t=subprocess.run([str(AR),str(p)],check=True,stdout=subprocess.PIPE,text=True).stdout
    assert f'mangled_bytes_sha256={hashlib.sha256(symbolic).hexdigest()} byte_length={len(symbolic)} symbolic_references=2' in t
    p=td/'swift-mangled-absent';p.write_bytes(swift64('mangled_absent'));j=analyze(p);s=j['macho_slices'][0]['swift']
    assert s['state']=='SWIFT_STRUCTURED' and s['coverage_state']=='STRUCTURED' and s['complete_type_closures']==1
    ty=s['types'][0];field=ty['fields'][0]
    assert ty['mangled_type_name']=='' and not ty['mangled_type_present'] and not ty['mangled_type_plain_text']
    assert field['mangled_type_name']=='' and not field['mangled_type_present'] and not field['mangled_type_plain_text']
    assert s['record_outcomes']['mangled_type_names_absent']==3 and s['record_outcomes']['mangled_type_names_symbolic']==0
    p=td/'swift-zero-field-sibling';p.write_bytes(swift64('zero_field_sibling'));j=analyze(p);s=j['macho_slices'][0]['swift']
    assert s['state']=='SWIFT_STRUCTURED' and s['coverage_state']=='STRUCTURED' and s['complete_type_closures']==1
    assert s['record_outcomes']['type_records_skipped']==1 and s['record_outcomes']['type_records_partial']==0
    p=td/'swift-partial-sibling';p.write_bytes(swift64('partial_sibling'));j=analyze(p);s=j['macho_slices'][0]['swift']
    assert s['state']=='SWIFT_STRUCTURED' and s['coverage_state']=='PARTIAL' and s['complete_type_closures']==1
    assert s['record_outcomes']['type_records_skipped']==1 and s['record_outcomes']['type_records_partial']==1
    assert s['record_outcomes']['type_records_unsupported']==1
    p=td/'swift-duplicate';p.write_bytes(swift64('duplicate'));j=analyze(p);s=j['macho_slices'][0]['swift']
    assert s['state']=='SWIFT_STRUCTURED' and s['coverage_state']=='PARTIAL' and s['complete_type_closures']==1
    assert s['record_outcomes']['type_records_skipped']==1 and s['record_outcomes']['type_records_partial']==1
    assert s['record_outcomes']['type_records_unsupported']==0
    # A well-ranged unknown LC preserves Mach-O validity but makes coverage partial.
    p=td/'swift-unknown-lc';p.write_bytes(swift64(unknown=True));j=analyze(p);m=j['macho_slices'][0]
    assert j['format']['kind']=='Mach-O' and m['coverage_state']=='PARTIAL'
    assert m['load_command_coverage_state']=='PARTIAL_UNKNOWN_COMMAND'
    assert m['unknown_load_command_count']==1 and m['unknown_load_commands']==[{'cmd':0x12345678,'offset':696,'size':8}]
    t=subprocess.run([str(AR),str(p)],check=True,stdout=subprocess.PIPE,text=True).stdout
    assert 'Unknown load command cmd=0x12345678 offset=0x2b8 size=8' in t
    # Encrypted Swift content is inventory-only, never decoded as metadata.
    p=td/'swift-encrypted';p.write_bytes(swift64('encrypted'));j=analyze(p);m=j['macho_slices'][0];s=m['swift']
    assert j['format']['kind']=='Mach-O' and m['coverage_state']=='PARTIAL'
    assert s['state']=='SWIFT_PRESENCE' and not s['structured'] and not s['types']
    fieldmd=[x for x in s['sections'] if x['name']=='__swift5_fieldmd'][0]
    assert fieldmd['encrypted_overlap'] and fieldmd['state']=='ENCRYPTED_CONTENT'
    # Relative-pointer direction, cycles, bounds, stride/count, string and
    # relation validation must fail closed without invalidating Mach-O framing.
    for mode in ('cycle','oob','bad_stride','bad_count','kind_mismatch','unterminated','invalid_utf8','mangled_empty','mangled_oob','symbolic_truncated','symbolic_pointer_truncated','indirect_parent'):
      p=td/('swift-'+mode);p.write_bytes(swift64(mode));j=analyze(p);m=j['macho_slices'][0];s=m['swift']
      assert j['format']['kind']=='Mach-O' and m['coverage_state']=='PARTIAL',mode
      assert s['state']=='SWIFT_PRESENCE' and not s['structured'] and s['coverage_state']=='PARTIAL' and s['error'],mode
      if mode=='mangled_empty':assert 'mangled type is empty' in s['error'],mode
      if mode=='mangled_oob':assert 'mangled type target is not in a file-backed section' in s['error'],mode
      if mode.startswith('symbolic_'):assert 'symbolic reference is truncated' in s['error'],mode
    # Retain bounded inventories while separately retaining a late unknown LC.
    p=td/'load-command-budget';p.write_bytes(many_load_commands());j=analyze(p);m=j['macho_slices'][0]
    assert j['format']['kind']=='Mach-O' and m['coverage_state']=='PARTIAL'
    assert m['load_command_count']==4098 and m['load_commands_retained']==4096 and m['load_commands_truncated']
    assert m['unknown_load_command_count']==1 and m['unknown_load_commands'][0]['cmd']==0x12345678
    assert 'load-command retention budget exceeded' in m['coverage_reasons']
    p=td/'swift-type-budget';p.write_bytes(swift_type_budget());j=analyze(p);m=j['macho_slices'][0];s=m['swift']
    assert j['format']['kind']=='Mach-O' and m['coverage_state']=='PARTIAL' and s['analysis_limited']
    assert s['state']=='SWIFT_PRESENCE' and s['error']=='Swift type-record budget exceeded'
    p=td/'libswift-dylib-only';p.write_bytes(thin64(dylib='/usr/lib/swift/libswiftCore.dylib'));j=analyze(p)
    assert not j['macho_slices'][0]['swift']['present']
    # Universal-container subtype, reserved, duplicate and alignment invariants.
    d=bytearray(fat([x86,arm]));struct.pack_into('>i',d,12,4);p=td/'fat-subtype-mismatch';p.write_bytes(d);assert analyze(p)['format']['kind']=='unknown'
    d=bytearray(fat([x86,arm],True));struct.pack_into('>I',d,36,1);p=td/'fat64-reserved';p.write_bytes(d);assert analyze(p)['format']['kind']=='unknown'
    p=td/'fat-duplicate-arch';p.write_bytes(fat([x86,x86]));assert analyze(p)['format']['kind']=='unknown'
    d=bytearray(fat([x86,arm]));struct.pack_into('>I',d,24,13);p=td/'fat-alignment';p.write_bytes(d);assert analyze(p)['format']['kind']=='unknown'
    p=td/'fat-arm64e';p.write_bytes(fat([x86,swift64()]));j=analyze(p)
    assert [x['architecture'] for x in j['macho_slices']]==['x86_64','arm64e']
  print('[PASS] Mach-O thin/FAT LE+BE + Swift/arm64e inventory + strict STRUCTURED closure + partial/budget boundaries')
if __name__=='__main__':main()
