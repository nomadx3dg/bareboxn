// Assembled with Keystone at 0x40000000 (message lives at 0x40010000):
//   movz x1,#0x4001,lsl #16 ; movz x2,#0x0900,lsl #16
//   loop: ldrb w3,[x1],#1 ; cbz w3,done ; strb w3,[x2] ; b loop
//   done: hlt #0
0xd2a80021,0xd2a12002,0x38401423,0x34000063,0x39000043,0x17fffffd,0xd4400000
