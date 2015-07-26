#ifndef _hash_H
#define _hash_H

ULONGLONG hashkey(PCHAR in) {
	ULONGLONG out = 0x1337;
	while (*in) {
		out ^= *in++ ^ *in << 5 * *in >> 1 & ~0xfffffffff0000000;
	}
	return out;
}


#endif // _hash_H