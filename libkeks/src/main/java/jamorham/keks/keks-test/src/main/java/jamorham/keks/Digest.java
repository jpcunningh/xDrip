package jamorham.keks;


import lombok.RequiredArgsConstructor;
import lombok.val;
import static jamorham.keks.util.Util.bytesToHex;

/**
 * JamOrHam
 */

@RequiredArgsConstructor
public class Digest {

    private byte[] store = new byte[0];
    private final byte[] destination;

    public void update(byte[] data) {
        val n = new byte[store.length + data.length];
        System.arraycopy(data, 0, n,  store.length, data.length);
        System.arraycopy(store, 0, n, 0, store.length);
        store = n;
    }

    public void doFinal() {
        System.out.println("store: " + bytesToHex(store));
        val result = SHA256.hash(store);
        System.arraycopy(result, 0, destination, 0, destination.length);
    }
}
