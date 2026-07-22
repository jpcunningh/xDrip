package jamorham.keks;

import static jamorham.keks.Config.Get.BOB;
import static jamorham.keks.Config.Get.ALICE;
import static jamorham.keks.util.Util.bytesToHex;
import static jamorham.keks.util.Util.hexStringToByteArray;

import java.math.BigInteger;

public class Test {

    public static void main(String[] args) {
        Context context = new Context();
        int arg = 0;

        if (args.length < 5) {
            System.out.println("Usage: java Test <txid> <keyA_hex> <keyB_hex> <userData1> <exponent_hex> <userData2> <exponent_hex> <userData3> <exponent_hex> <cert packet 1> <partC> <challenge>" + args.length);
            return;
        }

        String txId = args[arg++].replaceAll("\\s+", "");
        context.password = txId;

        String keyAHex = args[arg++].replaceAll("\\s+", "");
        String keyBHex = args[arg++].replaceAll("\\s+", "");

        if (keyAHex.length() != 64 || keyBHex.length() != 64) {
            System.err.println("Error: Both keys must be 32 bytes (64 hex characters each)");
            return;
        }

        context.keyA = KeyPair.fromPrivateKey(keyAHex);
        System.out.println("keyA:" + context.keyA.getPrivateKey().toString(16));

        context.KeyB = KeyPair.fromPrivateKey(keyBHex);
        System.out.println("keyB:" + context.KeyB.getPrivateKey().toString(16));

        String userDataHex1 = args[arg++].replaceAll("\\s+", ""); // remove spaces if any

        if (userDataHex1.length() != 320) {
            System.err.println("Error: Must provide exactly 160 bytes for userDataHex1 (320 hex characters)");
            return;
        }

        String exponentHex1 = args[arg++].replaceAll("\\s+", "");
        if (exponentHex1.length() != 64) {
            System.err.println("Error: Exponent must be 32 bytes (64 hex characters)");
            return;
        }

        String userDataHex2 = "", exponentHex2 = "";
        if (args.length > arg) {
            userDataHex2 = args[arg++].replaceAll("\\s+", ""); // remove spaces if any

            if (userDataHex2.length() != 320) {
                System.err.println("Error: Must provide exactly 160 bytes for userDataHex2 (320 hex characters)");
                return;
            }

            exponentHex2 = args[arg++].replaceAll("\\s+", "");
            if (exponentHex2.length() != 64) {
                System.err.println("Error: Exponent must be 32 bytes (64 hex characters)");
                return;
            }
        }

        String userDataHex3 = "", exponentHex3 = "";
        if (args.length > arg) {
            userDataHex3 = args[arg++].replaceAll("\\s+", ""); // remove spaces if any

            if (userDataHex3.length() != 320) {
                System.err.println("Error: Must provide exactly 160 bytes for userDataHex3 (320 hex characters)");
                return;
            }

            exponentHex3 = args[arg++].replaceAll("\\s+", "");
            if (exponentHex3.length() != 64) {
                System.err.println("Error: Exponent must be 32 bytes (64 hex characters)");
                return;
            }
        }

        String partCHex = "", challengeHex = "", certPacket1 = "";
        if (args.length > arg) {
            partCHex = args[arg++].replaceAll("\\s+", "");

            challengeHex = args[arg++].replaceAll("\\s+", "");

            certPacket1 = args[arg++].replaceAll("\\s+", "");
            if (certPacket1.length() != 984) {
                System.err.println("Error: Cert Packet 1 " + certPacket1.length()/2 + "B - must be 492 bytes (984 hex characters)");
                return;
            }
        }

        context.alice = ALICE.bytes;
        context.bob = BOB.bytes;

        System.out.println("\nreceived round1 packet");
        byte[] data = hexToBytes(userDataHex1);
        Packet packet = Packet.parse(data);

        context.packet[1] = packet;
        context.exponent = new BigInteger(exponentHex1, 16);
        context.useExponent = true;

        Calc.validateRound1Packet(context);

        Packet output = Calc.getRound1Packet(context);
        System.out.println("round1 packet:" + bytesToHex(output.output()));

        if (args.length >= 6) {
            System.out.println("\nreceived round2 packet");
            data = hexToBytes(userDataHex2);
            packet = Packet.parse(data);
            context.packet[2] = packet;

            context.exponent = new BigInteger(exponentHex2, 16);

            Calc.validateRound2Packet(context);
            output = Calc.getRound2Packet(context);
            System.out.println("round2 packet:" + bytesToHex(output.output()));
        }

        if (args.length >= 8) {
            System.out.println("\nreceived round3 packet");
            data = hexToBytes(userDataHex3);
            packet = Packet.parse(data);
            context.packet[3] = packet;

            context.exponent = new BigInteger(exponentHex3, 16);

            Calc.validateRound3Packet(context);
            output = Calc.getRound3Packet(context);
            System.out.println("round3 packet:" + bytesToHex(output.output()));
            System.out.println("shared key:" + bytesToHex(Calc.getSharedKey(context)));
        }

        if (args.length >= 10) {
            data = hexToBytes(certPacket1);
            packet = Packet.parse(data);

            data = hexToBytes(partCHex);
            byte[] challenge = hexToBytes(challengeHex);

            byte[] outputData = Calc.challenger(data, challenge);
            System.out.println("challenge response:" + bytesToHex(outputData));
        }
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
}
