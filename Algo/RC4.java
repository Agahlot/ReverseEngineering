public class RC4 {

	private String K;
	StringBuilder C;

	public RC4(String K) {
		this.K = K;
		C = new StringBuilder();
	}

	public StringBuilder rc4(String string) {
		int N = 256;
		/* State S */
		int[] S = new int[N];
		for (int i = 0; i < N; i++)
			S[i] = i;

		/* key-scheduling algorithm (KSA) */
		for (int i = 0, j = 0; i < N; i++) {
			j = ((j + S[i] + K.charAt(i % K.length())) % N);
			swap(S[i], S[j]);
		}

		Integer[] keyStream = new Integer[string.length()];
		/* pseudo-random generation algorithm (PRGA) */
		for (int i = 0, j = 0, k = 0; k < string.length(); k++) {
			i = (i + 1) % N;
			j = (j + S[i]) % N;
			swap(S[i], S[j]);

			keyStream[k] = S[(S[i] + S[j]) % N];
		}

		StringBuilder C = new StringBuilder();
		for (int i = 0; i < string.length(); i++) {
			C.append((char) (string.charAt(i) ^ keyStream[i]));
		}
		return C;
	}

	private void swap(int a, int b) {
		a ^= b;
		b ^= a;
		a ^= b;
	}

	public StringBuilder getCipher() {
		return C;
	}
}
