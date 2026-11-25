//! Exceptions and interrupts: entry stubs, the IDT, and the handler.
//!
//! Every vector funnels into one handler with a full register frame. A
//! breakpoint is counted and resumed (the boot self-test uses it to prove
//! the path works). Anything else is a fatal bugcheck with a register dump:
//! there is no SEH yet, so no driver or kernel code can handle a fault.

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Registers saved by the entry stub, lowest address first.
///
/// The floating-point part is what Windows saves in a trap frame: the
/// volatile registers XMM0-XMM5 and MXCSR. Kernel code that an interrupt
/// goes on to run (a driver's DPC, say) may use those freely, so the
/// interrupted code would otherwise find them changed. XMM6-XMM15 are
/// preserved by every function that uses them, under the calling
/// convention, and are not saved here.
#[repr(C)]
pub struct Frame {
    pub xmm: [[u64; 2]; 6],
    /// MXCSR of the interrupted code, in the low 32 bits.
    pub mxcsr: u64,
    /// Scratch: the stub loads the kernel's MXCSR from here.
    scratch: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const BREAKPOINT: u64 = 3;
const DOUBLE_FAULT: u64 = 8;
const PAGE_FAULT: u64 = 14;
/// `int 0x29`: `__fastfail`, how MSVC-built code reports fatal corruption
/// (a failed stack-cookie check, for one). The reason code is in rcx.
const FAST_FAIL: u64 = 0x29;

static BREAKPOINTS: AtomicU32 = AtomicU32::new(0);

/// How many breakpoint exceptions have been taken and resumed.
pub fn breakpoints() -> u32 {
    BREAKPOINTS.load(Ordering::Relaxed)
}

// Every vector gets a stub that pushes a zero error code where the CPU
// pushes none, then the vector number. The common path saves the
// general-purpose registers, then XMM0-XMM5 and MXCSR, gives the handler
// the kernel's own MXCSR (all exceptions masked, round to nearest), and
// calls it with the Windows x64 convention: argument in rcx, 32 bytes of
// shadow space, 16-byte aligned.
global_asm!(
    r#"
    .text
nk_trap_0:
    push 0
    push 0
    jmp nk_trap_common
nk_trap_1:
    push 0
    push 1
    jmp nk_trap_common
nk_trap_2:
    push 0
    push 2
    jmp nk_trap_common
nk_trap_3:
    push 0
    push 3
    jmp nk_trap_common
nk_trap_4:
    push 0
    push 4
    jmp nk_trap_common
nk_trap_5:
    push 0
    push 5
    jmp nk_trap_common
nk_trap_6:
    push 0
    push 6
    jmp nk_trap_common
nk_trap_7:
    push 0
    push 7
    jmp nk_trap_common
nk_trap_8:
    push 8
    jmp nk_trap_common
nk_trap_9:
    push 0
    push 9
    jmp nk_trap_common
nk_trap_10:
    push 10
    jmp nk_trap_common
nk_trap_11:
    push 11
    jmp nk_trap_common
nk_trap_12:
    push 12
    jmp nk_trap_common
nk_trap_13:
    push 13
    jmp nk_trap_common
nk_trap_14:
    push 14
    jmp nk_trap_common
nk_trap_15:
    push 0
    push 15
    jmp nk_trap_common
nk_trap_16:
    push 0
    push 16
    jmp nk_trap_common
nk_trap_17:
    push 17
    jmp nk_trap_common
nk_trap_18:
    push 0
    push 18
    jmp nk_trap_common
nk_trap_19:
    push 0
    push 19
    jmp nk_trap_common
nk_trap_20:
    push 0
    push 20
    jmp nk_trap_common
nk_trap_21:
    push 21
    jmp nk_trap_common
nk_trap_22:
    push 0
    push 22
    jmp nk_trap_common
nk_trap_23:
    push 0
    push 23
    jmp nk_trap_common
nk_trap_24:
    push 0
    push 24
    jmp nk_trap_common
nk_trap_25:
    push 0
    push 25
    jmp nk_trap_common
nk_trap_26:
    push 0
    push 26
    jmp nk_trap_common
nk_trap_27:
    push 0
    push 27
    jmp nk_trap_common
nk_trap_28:
    push 0
    push 28
    jmp nk_trap_common
nk_trap_29:
    push 29
    jmp nk_trap_common
nk_trap_30:
    push 30
    jmp nk_trap_common
nk_trap_31:
    push 0
    push 31
    jmp nk_trap_common
nk_trap_32:
    push 0
    push 32
    jmp nk_trap_common
nk_trap_33:
    push 0
    push 33
    jmp nk_trap_common
nk_trap_34:
    push 0
    push 34
    jmp nk_trap_common
nk_trap_35:
    push 0
    push 35
    jmp nk_trap_common
nk_trap_36:
    push 0
    push 36
    jmp nk_trap_common
nk_trap_37:
    push 0
    push 37
    jmp nk_trap_common
nk_trap_38:
    push 0
    push 38
    jmp nk_trap_common
nk_trap_39:
    push 0
    push 39
    jmp nk_trap_common
nk_trap_40:
    push 0
    push 40
    jmp nk_trap_common
nk_trap_41:
    push 0
    push 41
    jmp nk_trap_common
nk_trap_42:
    push 0
    push 42
    jmp nk_trap_common
nk_trap_43:
    push 0
    push 43
    jmp nk_trap_common
nk_trap_44:
    push 0
    push 44
    jmp nk_trap_common
nk_trap_45:
    push 0
    push 45
    jmp nk_trap_common
nk_trap_46:
    push 0
    push 46
    jmp nk_trap_common
nk_trap_47:
    push 0
    push 47
    jmp nk_trap_common
nk_trap_48:
    push 0
    push 48
    jmp nk_trap_common
nk_trap_49:
    push 0
    push 49
    jmp nk_trap_common
nk_trap_50:
    push 0
    push 50
    jmp nk_trap_common
nk_trap_51:
    push 0
    push 51
    jmp nk_trap_common
nk_trap_52:
    push 0
    push 52
    jmp nk_trap_common
nk_trap_53:
    push 0
    push 53
    jmp nk_trap_common
nk_trap_54:
    push 0
    push 54
    jmp nk_trap_common
nk_trap_55:
    push 0
    push 55
    jmp nk_trap_common
nk_trap_56:
    push 0
    push 56
    jmp nk_trap_common
nk_trap_57:
    push 0
    push 57
    jmp nk_trap_common
nk_trap_58:
    push 0
    push 58
    jmp nk_trap_common
nk_trap_59:
    push 0
    push 59
    jmp nk_trap_common
nk_trap_60:
    push 0
    push 60
    jmp nk_trap_common
nk_trap_61:
    push 0
    push 61
    jmp nk_trap_common
nk_trap_62:
    push 0
    push 62
    jmp nk_trap_common
nk_trap_63:
    push 0
    push 63
    jmp nk_trap_common
nk_trap_64:
    push 0
    push 64
    jmp nk_trap_common
nk_trap_65:
    push 0
    push 65
    jmp nk_trap_common
nk_trap_66:
    push 0
    push 66
    jmp nk_trap_common
nk_trap_67:
    push 0
    push 67
    jmp nk_trap_common
nk_trap_68:
    push 0
    push 68
    jmp nk_trap_common
nk_trap_69:
    push 0
    push 69
    jmp nk_trap_common
nk_trap_70:
    push 0
    push 70
    jmp nk_trap_common
nk_trap_71:
    push 0
    push 71
    jmp nk_trap_common
nk_trap_72:
    push 0
    push 72
    jmp nk_trap_common
nk_trap_73:
    push 0
    push 73
    jmp nk_trap_common
nk_trap_74:
    push 0
    push 74
    jmp nk_trap_common
nk_trap_75:
    push 0
    push 75
    jmp nk_trap_common
nk_trap_76:
    push 0
    push 76
    jmp nk_trap_common
nk_trap_77:
    push 0
    push 77
    jmp nk_trap_common
nk_trap_78:
    push 0
    push 78
    jmp nk_trap_common
nk_trap_79:
    push 0
    push 79
    jmp nk_trap_common
nk_trap_80:
    push 0
    push 80
    jmp nk_trap_common
nk_trap_81:
    push 0
    push 81
    jmp nk_trap_common
nk_trap_82:
    push 0
    push 82
    jmp nk_trap_common
nk_trap_83:
    push 0
    push 83
    jmp nk_trap_common
nk_trap_84:
    push 0
    push 84
    jmp nk_trap_common
nk_trap_85:
    push 0
    push 85
    jmp nk_trap_common
nk_trap_86:
    push 0
    push 86
    jmp nk_trap_common
nk_trap_87:
    push 0
    push 87
    jmp nk_trap_common
nk_trap_88:
    push 0
    push 88
    jmp nk_trap_common
nk_trap_89:
    push 0
    push 89
    jmp nk_trap_common
nk_trap_90:
    push 0
    push 90
    jmp nk_trap_common
nk_trap_91:
    push 0
    push 91
    jmp nk_trap_common
nk_trap_92:
    push 0
    push 92
    jmp nk_trap_common
nk_trap_93:
    push 0
    push 93
    jmp nk_trap_common
nk_trap_94:
    push 0
    push 94
    jmp nk_trap_common
nk_trap_95:
    push 0
    push 95
    jmp nk_trap_common
nk_trap_96:
    push 0
    push 96
    jmp nk_trap_common
nk_trap_97:
    push 0
    push 97
    jmp nk_trap_common
nk_trap_98:
    push 0
    push 98
    jmp nk_trap_common
nk_trap_99:
    push 0
    push 99
    jmp nk_trap_common
nk_trap_100:
    push 0
    push 100
    jmp nk_trap_common
nk_trap_101:
    push 0
    push 101
    jmp nk_trap_common
nk_trap_102:
    push 0
    push 102
    jmp nk_trap_common
nk_trap_103:
    push 0
    push 103
    jmp nk_trap_common
nk_trap_104:
    push 0
    push 104
    jmp nk_trap_common
nk_trap_105:
    push 0
    push 105
    jmp nk_trap_common
nk_trap_106:
    push 0
    push 106
    jmp nk_trap_common
nk_trap_107:
    push 0
    push 107
    jmp nk_trap_common
nk_trap_108:
    push 0
    push 108
    jmp nk_trap_common
nk_trap_109:
    push 0
    push 109
    jmp nk_trap_common
nk_trap_110:
    push 0
    push 110
    jmp nk_trap_common
nk_trap_111:
    push 0
    push 111
    jmp nk_trap_common
nk_trap_112:
    push 0
    push 112
    jmp nk_trap_common
nk_trap_113:
    push 0
    push 113
    jmp nk_trap_common
nk_trap_114:
    push 0
    push 114
    jmp nk_trap_common
nk_trap_115:
    push 0
    push 115
    jmp nk_trap_common
nk_trap_116:
    push 0
    push 116
    jmp nk_trap_common
nk_trap_117:
    push 0
    push 117
    jmp nk_trap_common
nk_trap_118:
    push 0
    push 118
    jmp nk_trap_common
nk_trap_119:
    push 0
    push 119
    jmp nk_trap_common
nk_trap_120:
    push 0
    push 120
    jmp nk_trap_common
nk_trap_121:
    push 0
    push 121
    jmp nk_trap_common
nk_trap_122:
    push 0
    push 122
    jmp nk_trap_common
nk_trap_123:
    push 0
    push 123
    jmp nk_trap_common
nk_trap_124:
    push 0
    push 124
    jmp nk_trap_common
nk_trap_125:
    push 0
    push 125
    jmp nk_trap_common
nk_trap_126:
    push 0
    push 126
    jmp nk_trap_common
nk_trap_127:
    push 0
    push 127
    jmp nk_trap_common
nk_trap_128:
    push 0
    push 128
    jmp nk_trap_common
nk_trap_129:
    push 0
    push 129
    jmp nk_trap_common
nk_trap_130:
    push 0
    push 130
    jmp nk_trap_common
nk_trap_131:
    push 0
    push 131
    jmp nk_trap_common
nk_trap_132:
    push 0
    push 132
    jmp nk_trap_common
nk_trap_133:
    push 0
    push 133
    jmp nk_trap_common
nk_trap_134:
    push 0
    push 134
    jmp nk_trap_common
nk_trap_135:
    push 0
    push 135
    jmp nk_trap_common
nk_trap_136:
    push 0
    push 136
    jmp nk_trap_common
nk_trap_137:
    push 0
    push 137
    jmp nk_trap_common
nk_trap_138:
    push 0
    push 138
    jmp nk_trap_common
nk_trap_139:
    push 0
    push 139
    jmp nk_trap_common
nk_trap_140:
    push 0
    push 140
    jmp nk_trap_common
nk_trap_141:
    push 0
    push 141
    jmp nk_trap_common
nk_trap_142:
    push 0
    push 142
    jmp nk_trap_common
nk_trap_143:
    push 0
    push 143
    jmp nk_trap_common
nk_trap_144:
    push 0
    push 144
    jmp nk_trap_common
nk_trap_145:
    push 0
    push 145
    jmp nk_trap_common
nk_trap_146:
    push 0
    push 146
    jmp nk_trap_common
nk_trap_147:
    push 0
    push 147
    jmp nk_trap_common
nk_trap_148:
    push 0
    push 148
    jmp nk_trap_common
nk_trap_149:
    push 0
    push 149
    jmp nk_trap_common
nk_trap_150:
    push 0
    push 150
    jmp nk_trap_common
nk_trap_151:
    push 0
    push 151
    jmp nk_trap_common
nk_trap_152:
    push 0
    push 152
    jmp nk_trap_common
nk_trap_153:
    push 0
    push 153
    jmp nk_trap_common
nk_trap_154:
    push 0
    push 154
    jmp nk_trap_common
nk_trap_155:
    push 0
    push 155
    jmp nk_trap_common
nk_trap_156:
    push 0
    push 156
    jmp nk_trap_common
nk_trap_157:
    push 0
    push 157
    jmp nk_trap_common
nk_trap_158:
    push 0
    push 158
    jmp nk_trap_common
nk_trap_159:
    push 0
    push 159
    jmp nk_trap_common
nk_trap_160:
    push 0
    push 160
    jmp nk_trap_common
nk_trap_161:
    push 0
    push 161
    jmp nk_trap_common
nk_trap_162:
    push 0
    push 162
    jmp nk_trap_common
nk_trap_163:
    push 0
    push 163
    jmp nk_trap_common
nk_trap_164:
    push 0
    push 164
    jmp nk_trap_common
nk_trap_165:
    push 0
    push 165
    jmp nk_trap_common
nk_trap_166:
    push 0
    push 166
    jmp nk_trap_common
nk_trap_167:
    push 0
    push 167
    jmp nk_trap_common
nk_trap_168:
    push 0
    push 168
    jmp nk_trap_common
nk_trap_169:
    push 0
    push 169
    jmp nk_trap_common
nk_trap_170:
    push 0
    push 170
    jmp nk_trap_common
nk_trap_171:
    push 0
    push 171
    jmp nk_trap_common
nk_trap_172:
    push 0
    push 172
    jmp nk_trap_common
nk_trap_173:
    push 0
    push 173
    jmp nk_trap_common
nk_trap_174:
    push 0
    push 174
    jmp nk_trap_common
nk_trap_175:
    push 0
    push 175
    jmp nk_trap_common
nk_trap_176:
    push 0
    push 176
    jmp nk_trap_common
nk_trap_177:
    push 0
    push 177
    jmp nk_trap_common
nk_trap_178:
    push 0
    push 178
    jmp nk_trap_common
nk_trap_179:
    push 0
    push 179
    jmp nk_trap_common
nk_trap_180:
    push 0
    push 180
    jmp nk_trap_common
nk_trap_181:
    push 0
    push 181
    jmp nk_trap_common
nk_trap_182:
    push 0
    push 182
    jmp nk_trap_common
nk_trap_183:
    push 0
    push 183
    jmp nk_trap_common
nk_trap_184:
    push 0
    push 184
    jmp nk_trap_common
nk_trap_185:
    push 0
    push 185
    jmp nk_trap_common
nk_trap_186:
    push 0
    push 186
    jmp nk_trap_common
nk_trap_187:
    push 0
    push 187
    jmp nk_trap_common
nk_trap_188:
    push 0
    push 188
    jmp nk_trap_common
nk_trap_189:
    push 0
    push 189
    jmp nk_trap_common
nk_trap_190:
    push 0
    push 190
    jmp nk_trap_common
nk_trap_191:
    push 0
    push 191
    jmp nk_trap_common
nk_trap_192:
    push 0
    push 192
    jmp nk_trap_common
nk_trap_193:
    push 0
    push 193
    jmp nk_trap_common
nk_trap_194:
    push 0
    push 194
    jmp nk_trap_common
nk_trap_195:
    push 0
    push 195
    jmp nk_trap_common
nk_trap_196:
    push 0
    push 196
    jmp nk_trap_common
nk_trap_197:
    push 0
    push 197
    jmp nk_trap_common
nk_trap_198:
    push 0
    push 198
    jmp nk_trap_common
nk_trap_199:
    push 0
    push 199
    jmp nk_trap_common
nk_trap_200:
    push 0
    push 200
    jmp nk_trap_common
nk_trap_201:
    push 0
    push 201
    jmp nk_trap_common
nk_trap_202:
    push 0
    push 202
    jmp nk_trap_common
nk_trap_203:
    push 0
    push 203
    jmp nk_trap_common
nk_trap_204:
    push 0
    push 204
    jmp nk_trap_common
nk_trap_205:
    push 0
    push 205
    jmp nk_trap_common
nk_trap_206:
    push 0
    push 206
    jmp nk_trap_common
nk_trap_207:
    push 0
    push 207
    jmp nk_trap_common
nk_trap_208:
    push 0
    push 208
    jmp nk_trap_common
nk_trap_209:
    push 0
    push 209
    jmp nk_trap_common
nk_trap_210:
    push 0
    push 210
    jmp nk_trap_common
nk_trap_211:
    push 0
    push 211
    jmp nk_trap_common
nk_trap_212:
    push 0
    push 212
    jmp nk_trap_common
nk_trap_213:
    push 0
    push 213
    jmp nk_trap_common
nk_trap_214:
    push 0
    push 214
    jmp nk_trap_common
nk_trap_215:
    push 0
    push 215
    jmp nk_trap_common
nk_trap_216:
    push 0
    push 216
    jmp nk_trap_common
nk_trap_217:
    push 0
    push 217
    jmp nk_trap_common
nk_trap_218:
    push 0
    push 218
    jmp nk_trap_common
nk_trap_219:
    push 0
    push 219
    jmp nk_trap_common
nk_trap_220:
    push 0
    push 220
    jmp nk_trap_common
nk_trap_221:
    push 0
    push 221
    jmp nk_trap_common
nk_trap_222:
    push 0
    push 222
    jmp nk_trap_common
nk_trap_223:
    push 0
    push 223
    jmp nk_trap_common
nk_trap_224:
    push 0
    push 224
    jmp nk_trap_common
nk_trap_225:
    push 0
    push 225
    jmp nk_trap_common
nk_trap_226:
    push 0
    push 226
    jmp nk_trap_common
nk_trap_227:
    push 0
    push 227
    jmp nk_trap_common
nk_trap_228:
    push 0
    push 228
    jmp nk_trap_common
nk_trap_229:
    push 0
    push 229
    jmp nk_trap_common
nk_trap_230:
    push 0
    push 230
    jmp nk_trap_common
nk_trap_231:
    push 0
    push 231
    jmp nk_trap_common
nk_trap_232:
    push 0
    push 232
    jmp nk_trap_common
nk_trap_233:
    push 0
    push 233
    jmp nk_trap_common
nk_trap_234:
    push 0
    push 234
    jmp nk_trap_common
nk_trap_235:
    push 0
    push 235
    jmp nk_trap_common
nk_trap_236:
    push 0
    push 236
    jmp nk_trap_common
nk_trap_237:
    push 0
    push 237
    jmp nk_trap_common
nk_trap_238:
    push 0
    push 238
    jmp nk_trap_common
nk_trap_239:
    push 0
    push 239
    jmp nk_trap_common
nk_trap_240:
    push 0
    push 240
    jmp nk_trap_common
nk_trap_241:
    push 0
    push 241
    jmp nk_trap_common
nk_trap_242:
    push 0
    push 242
    jmp nk_trap_common
nk_trap_243:
    push 0
    push 243
    jmp nk_trap_common
nk_trap_244:
    push 0
    push 244
    jmp nk_trap_common
nk_trap_245:
    push 0
    push 245
    jmp nk_trap_common
nk_trap_246:
    push 0
    push 246
    jmp nk_trap_common
nk_trap_247:
    push 0
    push 247
    jmp nk_trap_common
nk_trap_248:
    push 0
    push 248
    jmp nk_trap_common
nk_trap_249:
    push 0
    push 249
    jmp nk_trap_common
nk_trap_250:
    push 0
    push 250
    jmp nk_trap_common
nk_trap_251:
    push 0
    push 251
    jmp nk_trap_common
nk_trap_252:
    push 0
    push 252
    jmp nk_trap_common
nk_trap_253:
    push 0
    push 253
    jmp nk_trap_common
nk_trap_254:
    push 0
    push 254
    jmp nk_trap_common
nk_trap_255:
    push 0
    push 255
    jmp nk_trap_common
nk_trap_common:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp, 112
    movups xmmword ptr [rsp], xmm0
    movups xmmword ptr [rsp + 16], xmm1
    movups xmmword ptr [rsp + 32], xmm2
    movups xmmword ptr [rsp + 48], xmm3
    movups xmmword ptr [rsp + 64], xmm4
    movups xmmword ptr [rsp + 80], xmm5
    stmxcsr dword ptr [rsp + 96]
    mov dword ptr [rsp + 104], 0x1F80
    ldmxcsr dword ptr [rsp + 104]
    mov rcx, rsp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 32
    cld
    call {handler}
    mov rsp, rbp
    ldmxcsr dword ptr [rsp + 96]
    movups xmm0, xmmword ptr [rsp]
    movups xmm1, xmmword ptr [rsp + 16]
    movups xmm2, xmmword ptr [rsp + 32]
    movups xmm3, xmmword ptr [rsp + 48]
    movups xmm4, xmmword ptr [rsp + 64]
    movups xmm5, xmmword ptr [rsp + 80]
    add rsp, 112
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq

// For `fp_trap_test`. Load XMM0-XMM5 and MXCSR from the block at rcx, take
// a breakpoint, store what they hold afterwards in the block at rdx.
// A block is six 16-byte registers, then MXCSR.
    .globl nk_fp_trap_probe
nk_fp_trap_probe:
    sub rsp, 8
    stmxcsr dword ptr [rsp]
    movups xmm0, xmmword ptr [rcx]
    movups xmm1, xmmword ptr [rcx + 16]
    movups xmm2, xmmword ptr [rcx + 32]
    movups xmm3, xmmword ptr [rcx + 48]
    movups xmm4, xmmword ptr [rcx + 64]
    movups xmm5, xmmword ptr [rcx + 80]
    ldmxcsr dword ptr [rcx + 96]
    int3
    movups xmmword ptr [rdx], xmm0
    movups xmmword ptr [rdx + 16], xmm1
    movups xmmword ptr [rdx + 32], xmm2
    movups xmmword ptr [rdx + 48], xmm3
    movups xmmword ptr [rdx + 64], xmm4
    movups xmmword ptr [rdx + 80], xmm5
    stmxcsr dword ptr [rdx + 96]
    ldmxcsr dword ptr [rsp]
    add rsp, 8
    ret

// What code run from an interrupt is entitled to do: overwrite every
// volatile vector register. Stores the MXCSR it runs with at rcx.
    .globl nk_fp_clobber
nk_fp_clobber:
    stmxcsr dword ptr [rcx]
    pcmpeqd xmm0, xmm0
    movdqa xmm1, xmm0
    movdqa xmm2, xmm0
    movdqa xmm3, xmm0
    movdqa xmm4, xmm0
    movdqa xmm5, xmm0
    ret

    .section .rdata
    .balign 8
    .globl nk_trap_table
nk_trap_table:
    .quad nk_trap_0
    .quad nk_trap_1
    .quad nk_trap_2
    .quad nk_trap_3
    .quad nk_trap_4
    .quad nk_trap_5
    .quad nk_trap_6
    .quad nk_trap_7
    .quad nk_trap_8
    .quad nk_trap_9
    .quad nk_trap_10
    .quad nk_trap_11
    .quad nk_trap_12
    .quad nk_trap_13
    .quad nk_trap_14
    .quad nk_trap_15
    .quad nk_trap_16
    .quad nk_trap_17
    .quad nk_trap_18
    .quad nk_trap_19
    .quad nk_trap_20
    .quad nk_trap_21
    .quad nk_trap_22
    .quad nk_trap_23
    .quad nk_trap_24
    .quad nk_trap_25
    .quad nk_trap_26
    .quad nk_trap_27
    .quad nk_trap_28
    .quad nk_trap_29
    .quad nk_trap_30
    .quad nk_trap_31
    .quad nk_trap_32
    .quad nk_trap_33
    .quad nk_trap_34
    .quad nk_trap_35
    .quad nk_trap_36
    .quad nk_trap_37
    .quad nk_trap_38
    .quad nk_trap_39
    .quad nk_trap_40
    .quad nk_trap_41
    .quad nk_trap_42
    .quad nk_trap_43
    .quad nk_trap_44
    .quad nk_trap_45
    .quad nk_trap_46
    .quad nk_trap_47
    .quad nk_trap_48
    .quad nk_trap_49
    .quad nk_trap_50
    .quad nk_trap_51
    .quad nk_trap_52
    .quad nk_trap_53
    .quad nk_trap_54
    .quad nk_trap_55
    .quad nk_trap_56
    .quad nk_trap_57
    .quad nk_trap_58
    .quad nk_trap_59
    .quad nk_trap_60
    .quad nk_trap_61
    .quad nk_trap_62
    .quad nk_trap_63
    .quad nk_trap_64
    .quad nk_trap_65
    .quad nk_trap_66
    .quad nk_trap_67
    .quad nk_trap_68
    .quad nk_trap_69
    .quad nk_trap_70
    .quad nk_trap_71
    .quad nk_trap_72
    .quad nk_trap_73
    .quad nk_trap_74
    .quad nk_trap_75
    .quad nk_trap_76
    .quad nk_trap_77
    .quad nk_trap_78
    .quad nk_trap_79
    .quad nk_trap_80
    .quad nk_trap_81
    .quad nk_trap_82
    .quad nk_trap_83
    .quad nk_trap_84
    .quad nk_trap_85
    .quad nk_trap_86
    .quad nk_trap_87
    .quad nk_trap_88
    .quad nk_trap_89
    .quad nk_trap_90
    .quad nk_trap_91
    .quad nk_trap_92
    .quad nk_trap_93
    .quad nk_trap_94
    .quad nk_trap_95
    .quad nk_trap_96
    .quad nk_trap_97
    .quad nk_trap_98
    .quad nk_trap_99
    .quad nk_trap_100
    .quad nk_trap_101
    .quad nk_trap_102
    .quad nk_trap_103
    .quad nk_trap_104
    .quad nk_trap_105
    .quad nk_trap_106
    .quad nk_trap_107
    .quad nk_trap_108
    .quad nk_trap_109
    .quad nk_trap_110
    .quad nk_trap_111
    .quad nk_trap_112
    .quad nk_trap_113
    .quad nk_trap_114
    .quad nk_trap_115
    .quad nk_trap_116
    .quad nk_trap_117
    .quad nk_trap_118
    .quad nk_trap_119
    .quad nk_trap_120
    .quad nk_trap_121
    .quad nk_trap_122
    .quad nk_trap_123
    .quad nk_trap_124
    .quad nk_trap_125
    .quad nk_trap_126
    .quad nk_trap_127
    .quad nk_trap_128
    .quad nk_trap_129
    .quad nk_trap_130
    .quad nk_trap_131
    .quad nk_trap_132
    .quad nk_trap_133
    .quad nk_trap_134
    .quad nk_trap_135
    .quad nk_trap_136
    .quad nk_trap_137
    .quad nk_trap_138
    .quad nk_trap_139
    .quad nk_trap_140
    .quad nk_trap_141
    .quad nk_trap_142
    .quad nk_trap_143
    .quad nk_trap_144
    .quad nk_trap_145
    .quad nk_trap_146
    .quad nk_trap_147
    .quad nk_trap_148
    .quad nk_trap_149
    .quad nk_trap_150
    .quad nk_trap_151
    .quad nk_trap_152
    .quad nk_trap_153
    .quad nk_trap_154
    .quad nk_trap_155
    .quad nk_trap_156
    .quad nk_trap_157
    .quad nk_trap_158
    .quad nk_trap_159
    .quad nk_trap_160
    .quad nk_trap_161
    .quad nk_trap_162
    .quad nk_trap_163
    .quad nk_trap_164
    .quad nk_trap_165
    .quad nk_trap_166
    .quad nk_trap_167
    .quad nk_trap_168
    .quad nk_trap_169
    .quad nk_trap_170
    .quad nk_trap_171
    .quad nk_trap_172
    .quad nk_trap_173
    .quad nk_trap_174
    .quad nk_trap_175
    .quad nk_trap_176
    .quad nk_trap_177
    .quad nk_trap_178
    .quad nk_trap_179
    .quad nk_trap_180
    .quad nk_trap_181
    .quad nk_trap_182
    .quad nk_trap_183
    .quad nk_trap_184
    .quad nk_trap_185
    .quad nk_trap_186
    .quad nk_trap_187
    .quad nk_trap_188
    .quad nk_trap_189
    .quad nk_trap_190
    .quad nk_trap_191
    .quad nk_trap_192
    .quad nk_trap_193
    .quad nk_trap_194
    .quad nk_trap_195
    .quad nk_trap_196
    .quad nk_trap_197
    .quad nk_trap_198
    .quad nk_trap_199
    .quad nk_trap_200
    .quad nk_trap_201
    .quad nk_trap_202
    .quad nk_trap_203
    .quad nk_trap_204
    .quad nk_trap_205
    .quad nk_trap_206
    .quad nk_trap_207
    .quad nk_trap_208
    .quad nk_trap_209
    .quad nk_trap_210
    .quad nk_trap_211
    .quad nk_trap_212
    .quad nk_trap_213
    .quad nk_trap_214
    .quad nk_trap_215
    .quad nk_trap_216
    .quad nk_trap_217
    .quad nk_trap_218
    .quad nk_trap_219
    .quad nk_trap_220
    .quad nk_trap_221
    .quad nk_trap_222
    .quad nk_trap_223
    .quad nk_trap_224
    .quad nk_trap_225
    .quad nk_trap_226
    .quad nk_trap_227
    .quad nk_trap_228
    .quad nk_trap_229
    .quad nk_trap_230
    .quad nk_trap_231
    .quad nk_trap_232
    .quad nk_trap_233
    .quad nk_trap_234
    .quad nk_trap_235
    .quad nk_trap_236
    .quad nk_trap_237
    .quad nk_trap_238
    .quad nk_trap_239
    .quad nk_trap_240
    .quad nk_trap_241
    .quad nk_trap_242
    .quad nk_trap_243
    .quad nk_trap_244
    .quad nk_trap_245
    .quad nk_trap_246
    .quad nk_trap_247
    .quad nk_trap_248
    .quad nk_trap_249
    .quad nk_trap_250
    .quad nk_trap_251
    .quad nk_trap_252
    .quad nk_trap_253
    .quad nk_trap_254
    .quad nk_trap_255
"#,
    handler = sym trap_handler,
);

unsafe extern "C" {
    /// Addresses of the 256 entry stubs, by vector.
    static nk_trap_table: [u64; 256];
    fn nk_fp_trap_probe(load: *const FpBlock, store: *mut FpBlock);
    fn nk_fp_clobber(mxcsr: *mut u32);
}

/// XMM0-XMM5 and MXCSR, as `nk_fp_trap_probe` loads and stores them.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FpBlock {
    xmm: [[u64; 2]; 6],
    mxcsr: u32,
}

/// MXCSR as the kernel runs: every exception masked, round to nearest.
const KERNEL_MXCSR: u32 = 0x1F80;
/// Set while `fp_trap_test` wants the breakpoint handler to overwrite the
/// volatile vector registers.
static FP_CLOBBER: AtomicBool = AtomicBool::new(false);
/// The MXCSR the handler ran with during that breakpoint.
static HANDLER_MXCSR: AtomicU32 = AtomicU32::new(0);

/// An exception must not disturb the vector registers or MXCSR of the
/// code it interrupts, even when the handler (as a driver's code may)
/// uses every volatile one; and the handler must run with the kernel's
/// own MXCSR, not the interrupted code's.
pub fn fp_trap_test() -> Result<(), &'static str> {
    let mut load = FpBlock {
        xmm: [[0; 2]; 6],
        // Round toward zero: a value no kernel code sets, so finding it
        // again afterwards means it was restored, not merely left alone.
        mxcsr: KERNEL_MXCSR | 0x6000,
    };
    for (i, reg) in load.xmm.iter_mut().enumerate() {
        *reg = [0x1111_1111_1111_1111 * (i as u64 + 1), !(i as u64)];
    }
    let mut store = FpBlock {
        xmm: [[0; 2]; 6],
        mxcsr: 0,
    };
    FP_CLOBBER.store(true, Ordering::Relaxed);
    // SAFETY: both blocks are live and of the size the probe reads and
    // writes; it restores the caller's MXCSR, and XMM0-XMM5 are volatile.
    unsafe { nk_fp_trap_probe(&raw const load, &raw mut store) };
    FP_CLOBBER.store(false, Ordering::Relaxed);
    if HANDLER_MXCSR.load(Ordering::Relaxed) != KERNEL_MXCSR {
        return Err("the handler ran with the interrupted code's MXCSR");
    }
    if store.mxcsr != load.mxcsr {
        return Err("MXCSR was not restored after the exception");
    }
    if store.xmm != load.xmm {
        return Err("a volatile vector register was not restored after the exception");
    }
    Ok(())
}

extern "C" fn trap_handler(frame: &mut Frame) {
    if frame.vector == BREAKPOINT {
        // `int3` is a trap: rip already points past it.
        BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        if FP_CLOBBER.load(Ordering::Relaxed) {
            let mut mxcsr = 0;
            // SAFETY: the routine writes one `u32` and volatile registers.
            unsafe { nk_fp_clobber(&raw mut mxcsr) };
            HANDLER_MXCSR.store(mxcsr, Ordering::Relaxed);
        }
        return;
    }
    let cr2: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack)) };
    // A stack that overflows faults on the unmapped memory below it. The
    // page fault cannot push its own frame there, so it arrives as a
    // double fault, on the stack kept for that.
    let overflow = matches!(frame.vector, DOUBLE_FAULT | PAGE_FAULT)
        && crate::mm::stack::is_overflow(super::cpu::kernel_stack(), cr2);
    let what = match frame.vector {
        _ if overflow => "kernel stack overflow",
        0 => "divide error",
        6 => "invalid opcode",
        DOUBLE_FAULT => "double fault",
        13 => "general protection fault",
        PAGE_FAULT => "page fault",
        FAST_FAIL => "driver fast-fail (reason code in rcx)",
        32.. => "unexpected interrupt",
        _ => "exception",
    };
    crate::kd::bugcheck(format_args!(
        "{what} (vector {}, error {:#x}) at rip={:#018x}\n\
         cr2={cr2:#018x} rsp={:#018x} rflags={:#x} cs={:#x}\n\
         rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}\n\
         rsi={:#018x} rdi={:#018x} rbp={:#018x} r8 ={:#018x}\n\
         r9 ={:#018x} r10={:#018x} r11={:#018x} r12={:#018x}\n\
         r13={:#018x} r14={:#018x} r15={:#018x}",
        frame.vector,
        frame.error,
        frame.rip,
        frame.rsp,
        frame.rflags,
        frame.cs,
        frame.rax,
        frame.rbx,
        frame.rcx,
        frame.rdx,
        frame.rsi,
        frame.rdi,
        frame.rbp,
        frame.r8,
        frame.r9,
        frame.r10,
        frame.r11,
        frame.r12,
        frame.r13,
        frame.r14,
        frame.r15,
    ))
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    kind: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

/// Present, ring 0, 64-bit interrupt gate.
const INTERRUPT_GATE: u8 = 0x8E;

struct Idt(UnsafeCell<[Gate; 256]>);

// SAFETY: written once by `init` on the boot CPU before interrupts or
// other CPUs exist, read-only afterwards.
unsafe impl Sync for Idt {}

static IDT: Idt = Idt(UnsafeCell::new(
    [Gate {
        offset_low: 0,
        selector: 0,
        ist: 0,
        kind: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    }; 256],
));

/// Build and load the IDT. `code_selector` is the kernel code segment;
/// `fault_ist` is the interrupt-stack index for faults that must not trust
/// the current stack (double fault, NMI).
pub fn init(code_selector: u16, fault_ist: u8) {
    // SAFETY: the assembly above defines 256 addresses at this symbol.
    let stubs = unsafe { &nk_trap_table };
    // SAFETY: single-threaded early boot; nothing else references the IDT.
    let idt = unsafe { &mut *IDT.0.get() };
    for (vector, gate) in idt.iter_mut().enumerate() {
        let addr = stubs[vector];
        *gate = Gate {
            offset_low: addr as u16,
            selector: code_selector,
            ist: if vector == 2 || vector == 8 {
                fault_ist
            } else {
                0
            },
            kind: INTERRUPT_GATE,
            offset_mid: (addr >> 16) as u16,
            offset_high: (addr >> 32) as u32,
            reserved: 0,
        };
    }
    let pointer = super::cpu::TablePointer {
        limit: (size_of::<[Gate; 256]>() - 1) as u16,
        base: IDT.0.get() as u64,
    };
    // SAFETY: the IDT is static and fully initialised; every gate targets a
    // stub that saves state and reaches `trap_handler`.
    unsafe {
        core::arch::asm!("lidt [{}]", in(reg) &raw const pointer, options(readonly, nostack))
    };
}

/// Execute a breakpoint instruction.
pub fn breakpoint() {
    // SAFETY: `int3` traps to the handler above, which resumes after it.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
}
