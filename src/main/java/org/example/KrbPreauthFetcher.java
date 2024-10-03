package org.example;

import com.beanit.asn1bean.ber.ReverseByteArrayOutputStream;
import com.beanit.asn1bean.ber.types.BerInteger;
import com.beanit.asn1bean.ber.types.BerOctetString;
import kerberos.*;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.ClientUtil;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

import static java.lang.Thread.sleep;

public class KrbPreauthFetcher {
    private static final int BUFFER_MAX_LEN = 1024;

    final private static int KDC_OPT_FORWARDABLE = 0x40000000;
    final private static int KDC_OPT_FORWARDED = 0x20000000;
    final private static int KDC_OPT_PROXIABLE = 0x10000000;
    final private static int KDC_OPT_PROXY = 0x08000000;
    final private static int KDC_OPT_ALLOW_POSTDATE = 0x04000000;
    final private static int KDC_OPT_POSTDATED = 0x02000000;
    final private static int KDC_OPT_RENEWABLE = 0x00800000;
    final private static int KDC_OPT_CNAME_IN_ADDL_TKT = 0x00020000;
    final private static int KDC_OPT_CANONICALIZE = 0x00010000;
    final private static int KDC_OPT_REQUEST_ANONYMOUS = 0x00008000;
    final private static int KDC_OPT_DISABLE_TRANSITED_CHECK = 0x00000020;
    final private static int KDC_OPT_RENEWABLE_OK = 0x00000010;
    final private static int KDC_OPT_ENC_TKT_IN_SKEY = 0x00000008;
    final private static int KDC_OPT_RENEW = 0x00000002;
    final private static int KDC_OPT_VALIDATE = 0x00000001;


    public static void main( String[] args ) throws IOException, InterruptedException, KrbException {
        KrbConfig conf = ClientUtil.getDefaultConfig();

        // parse principal into username and realm
        String principal = args[0];
        String username;
        String realm;
        if (principal.contains("@")) {
            String[] parts = principal.split("@");
            username = parts[0];
            realm = parts[1];
        } else {
            username = principal;
            realm = conf.getDefaultRealm();
        }

        // get KDC for the realm
        List<Object> kdcs = conf.getRealmSectionItems(realm, "kdc");
        if (kdcs.size() == 0)
            throw new RuntimeException("Could not find KDC for realm " + realm);
        String kdc = (String) kdcs.get(0);
        int port = 88;
        if (kdc.contains(":")) {
            String[] parts = kdc.split(":");
            kdc = parts[0];
            port = Integer.parseInt(parts[1]);
        }

        // get list of encryption types
        List<EncryptionType> eTypesList = conf.getEncryptionTypes();
        int[] eTypes = new int[eTypesList.size()];
        for(int i = 0; i < eTypesList.size(); i++) eTypes[i] = eTypesList.get(i).getValue();

        // craft the AS-REQ
        ASREQ asReq = createAsReq(
                username,
                realm,
                KDC_OPT_FORWARDABLE + KDC_OPT_CANONICALIZE + KDC_OPT_RENEWABLE_OK,
                eTypes
        );

        // encode the request
        final byte[] buffer = new byte[BUFFER_MAX_LEN];
        ReverseByteArrayOutputStream os = new ReverseByteArrayOutputStream(buffer);
        int encodedLength = asReq.encode(os);
        byte[] encodedBytes = Arrays.copyOfRange(buffer, BUFFER_MAX_LEN - encodedLength, BUFFER_MAX_LEN);

        // prepend the length to create the request payload
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(encodedLength);
        dos.write(encodedBytes);
        byte[] requestPayload = baos.toByteArray();

        // send request to KDC
        byte[] responsePayload = processKdcRequest(kdc, port, requestPayload);

        // check length and extract payload
        int length = ByteBuffer.wrap(responsePayload, 0, 4).getInt();
        if (length != responsePayload.length - 4)
            throw new RuntimeException("Payload length is incorrect. Expected: " + length + ", Received: " + (responsePayload.length - 4));
        byte[] responseData = Arrays.copyOfRange(responsePayload, 4, 4 + length);

        // process the response. We are expecting a PREAUTH ERROR in the form of a KRB-ERROR response
        if (ASREP.tag.tagBytes[0] == responseData[0]) {
            // AS-REP response
            // if a AS-REP is received, prints it for debugging purposes
            ASREP asRep = new ASREP();
            asRep.decode(new ByteArrayInputStream(responseData));
            System.out.println(asRep);
        } else if (KRBERROR.tag.tagBytes[0] == responseData[0]) {
            // KRB-ERROR response
            KRBERROR error = new KRBERROR();
            error.decode(new ByteArrayInputStream(responseData));
            // check if this is a pre-auth error
            if (error.getErrorCode().intValue() == 25) {
                METHODDATA eData = new METHODDATA();
                eData.decode(new ByteArrayInputStream(error.getEData().value));
                // Look for padata-type = 19 (pa-etype-info2, DER encoding of ETYPE-INFO2)
                for (PADATA pa : eData.getPADATA()) {
                    if (pa.getPadataType().intValue() == 19) {
                        ETYPEINFO2 eti2 = new ETYPEINFO2();
                        eti2.decode(new ByteArrayInputStream(pa.getPadataValue().value));
                        for (ETYPEINFO2ENTRY e : eti2.getETYPEINFO2ENTRY()) {
                            System.out.println("- Encryption type: " + e.getEtype());
                            System.out.println("  Salt: 0x" + bytesToHex(e.getSalt().value));
                        }
                    }
                }
            } else {
                int errorCode = error.getErrorCode().intValue();
                throw new RuntimeException("Unexpected KRB-ERROR code " + errorCode + " (" + KRB_ERRORS.get(errorCode) + ")");
            }
        } else {
            System.out.println("Tag not recognized: " + bytesToHex(Arrays.copyOfRange(responseData, 0, 1)));
        }
    }

    private static ASREQ createAsReq(String username, String realm, int kdcOptions, int[] encryptionTypes) throws IOException {
        ASREQ asReq = new ASREQ();
        asReq.setPvno(new BerInteger(5));
        asReq.setMsgType(new BerInteger(10));
        asReq.setPadata(createKdcReqPaData());
        asReq.setReqBody(createKdcReqBody(username, realm, kdcOptions, encryptionTypes));
        return asReq;
    }

    private static KDCREQ.Padata createKdcReqPaData() {
        KDCREQ.Padata kdcReqPaData = new KDCREQ.Padata();
        kdcReqPaData.getPADATA().add(createPaData());
        return kdcReqPaData;
    }

    private static PADATA createPaData() {
        PADATA padata = new PADATA();
        padata.setPadataType(new Int32(0x95));
        padata.setPadataValue(new BerOctetString("".getBytes(StandardCharsets.UTF_8)));
        return padata;
    }

    private static KDCREQBODY createKdcReqBody(String username, String realm, int kdcOptions, int[] encryptionTypes) throws IOException {
        Calendar c = Calendar.getInstance();
        c.add(Calendar.HOUR, 1);
        SimpleDateFormat f = new SimpleDateFormat("yyyyMMddHHmmss");
        String till = f.format(c.getTime()) + "Z";

        KDCREQBODY reqBody = new KDCREQBODY();
        reqBody.setKdcOptions(new KDCOptions(ByteBuffer.allocate(4).putInt(kdcOptions).array(), 32));
        reqBody.setCname(createPrincipalName(1, username));
        reqBody.setRealm(new Realm(realm.getBytes(StandardCharsets.UTF_8)));
        reqBody.setSname(createPrincipalName(2, "krbtgt", realm));
        reqBody.setTill(new KerberosTime(till.getBytes(StandardCharsets.UTF_8)));
        reqBody.setNonce(new UInt32(new Random().nextLong() % 2147483647L));
        reqBody.setEtype(createKdcReqBodyEType(encryptionTypes));
        return reqBody;
    }

    private static PrincipalName createPrincipalName(int nameType, String ... names) {
        PrincipalName principalName = new PrincipalName();
        principalName.setNameType(new Int32(nameType));
        PrincipalName.NameString nameString = new PrincipalName.NameString();
        for (String name : names)
            nameString.getKerberosString().add(new KerberosString(name.getBytes(StandardCharsets.UTF_8)));
        principalName.setNameString(nameString);
        return principalName;
    }

    private static KDCREQBODY.Etype createKdcReqBodyEType(int ... eTypes) {
        KDCREQBODY.Etype eType = new KDCREQBODY.Etype();
        for (int type : eTypes) eType.getInt32().add(new Int32(type));
        return eType;
    }

    private static byte[] processKdcRequest(String ip, int port, byte[] requestPayload) throws IOException, InterruptedException {
        try (Socket clientSocket = new Socket(ip, port)) {
            clientSocket.getOutputStream().write(requestPayload);
            byte[] buffer = new byte[BUFFER_MAX_LEN];
            int readAttempts = 0;
            int offset = 0;
            while (true) {
                int n = clientSocket.getInputStream().read(buffer, offset, BUFFER_MAX_LEN - offset);
                if (n < 0) break;
                offset += n;
                readAttempts += 1;
                if (readAttempts >= 30)
                    throw new RuntimeException("Timeout receiving ASREP");
                sleep(100L);
            }
            if (offset == 0)
                throw new RuntimeException("No answer from KDC");
            return Arrays.copyOfRange(buffer, 0, offset);
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static final HashMap<Integer, String> KRB_ERRORS = new HashMap<Integer, String>();
    static {
        KRB_ERRORS.put(0, "[KDC_ERR_NONE] No error");
        KRB_ERRORS.put(1, "[KDC_ERR_NAME_EXP] Client's entry in database has expired");
        KRB_ERRORS.put(2, "[KDC_ERR_SERVICE_EXP] Server's entry in database has expired");
        KRB_ERRORS.put(3, "[KDC_ERR_BAD_PVNO] Requested protocol version number not supported");
        KRB_ERRORS.put(4, "[KDC_ERR_C_OLD_MAST_KVNO] Client's key encrypted in old master key");
        KRB_ERRORS.put(5, "[KDC_ERR_S_OLD_MAST_KVNO] Server's key encrypted in old master key");
        KRB_ERRORS.put(6, "[KDC_ERR_C_PRINCIPAL_UNKNOWN] Client not found in Kerberos database");
        KRB_ERRORS.put(7, "[KDC_ERR_S_PRINCIPAL_UNKNOWN] Server not found in Kerberos database");
        KRB_ERRORS.put(8, "[KDC_ERR_PRINCIPAL_NOT_UNIQUE] Multiple principal entries in database");
        KRB_ERRORS.put(9, "[KDC_ERR_NULL_KEY] The client or server has a null key");
        KRB_ERRORS.put(10, "[KDC_ERR_CANNOT_POSTDATE] Ticket not eligible for postdating");
        KRB_ERRORS.put(11, "[KDC_ERR_NEVER_VALID] Requested starttime is later than end time");
        KRB_ERRORS.put(12, "[KDC_ERR_POLICY] KDC policy rejects request");
        KRB_ERRORS.put(13, "[KDC_ERR_BADOPTION] KDC cannot accommodate requested option");
        KRB_ERRORS.put(14, "[KDC_ERR_ETYPE_NOSUPP] KDC has no support for encryption type");
        KRB_ERRORS.put(15, "[KDC_ERR_SUMTYPE_NOSUPP] KDC has no support for checksum type");
        KRB_ERRORS.put(16, "[KDC_ERR_PADATA_TYPE_NOSUPP] KDC has no support for padata type");
        KRB_ERRORS.put(17, "[KDC_ERR_TRTYPE_NOSUPP] KDC has no support for transited type");
        KRB_ERRORS.put(18, "[KDC_ERR_CLIENT_REVOKED] Clients credentials have been revoked");
        KRB_ERRORS.put(19, "[KDC_ERR_SERVICE_REVOKED] Credentials for server have been revoked");
        KRB_ERRORS.put(20, "[KDC_ERR_TGT_REVOKED] TGT has been revoked");
        KRB_ERRORS.put(21, "[KDC_ERR_CLIENT_NOTYET] Client not yet valid; try again later");
        KRB_ERRORS.put(22, "[KDC_ERR_SERVICE_NOTYET] Server not yet valid; try again later");
        KRB_ERRORS.put(23, "[KDC_ERR_KEY_EXPIRED] Password has expired; change password to reset");
        KRB_ERRORS.put(24, "[KDC_ERR_PREAUTH_FAILED] Pre-authentication information was invalid");
        KRB_ERRORS.put(25, "[KDC_ERR_PREAUTH_REQUIRED] Additional pre- authentication required");
        KRB_ERRORS.put(26, "[KDC_ERR_SERVER_NOMATCH] Requested server and ticket don't match");
        KRB_ERRORS.put(27, "[KDC_ERR_MUST_USE_USER2USER] Server principal valid for user2user only");
        KRB_ERRORS.put(28, "[KDC_ERR_PATH_NOT_ACCEPTED] KDC Policy rejects");
        KRB_ERRORS.put(29, "[KDC_ERR_SVC_UNAVAILABLE] A service is not available");
        KRB_ERRORS.put(31, "[KRB_AP_ERR_BAD_INTEGRITY] Integrity check on decrypted field failed");
        KRB_ERRORS.put(32, "[KRB_AP_ERR_TKT_EXPIRED] Ticket expired");
        KRB_ERRORS.put(33, "[KRB_AP_ERR_TKT_NYV] Ticket not yet valid");
        KRB_ERRORS.put(34, "[KRB_AP_ERR_REPEAT] Request is a replay");
        KRB_ERRORS.put(35, "[KRB_AP_ERR_NOT_US] The ticket isn't for us");
        KRB_ERRORS.put(36, "[KRB_AP_ERR_BADMATCH] Ticket and authenticator don't match");
        KRB_ERRORS.put(37, "[KRB_AP_ERR_SKEW] Clock skew too great");
        KRB_ERRORS.put(38, "[KRB_AP_ERR_BADADDR] Incorrect net address");
        KRB_ERRORS.put(39, "[KRB_AP_ERR_BADVERSION] Protocol version mismatch");
        KRB_ERRORS.put(40, "[KRB_AP_ERR_MSG_TYPE] Invalid msg type");
        KRB_ERRORS.put(41, "[KRB_AP_ERR_MODIFIED] Message stream modified");
        KRB_ERRORS.put(42, "[KRB_AP_ERR_BADORDER] Message out of order");
        KRB_ERRORS.put(44, "[KRB_AP_ERR_BADKEYVER] Specified version of key is not available");
        KRB_ERRORS.put(45, "[KRB_AP_ERR_NOKEY] Service key not available");
        KRB_ERRORS.put(46, "[KRB_AP_ERR_MUT_FAIL] Mutual authentication failed");
        KRB_ERRORS.put(47, "[KRB_AP_ERR_BADDIRECTION] Incorrect message direction");
        KRB_ERRORS.put(48, "[KRB_AP_ERR_METHOD] Alternative authentication method required");
        KRB_ERRORS.put(49, "[KRB_AP_ERR_BADSEQ] Incorrect sequence number in message");
        KRB_ERRORS.put(50, "[KRB_AP_ERR_INAPP_CKSUM] Inappropriate type of checksum in message");
        KRB_ERRORS.put(51, "[KRB_AP_PATH_NOT_ACCEPTED] Policy rejects transited path");
        KRB_ERRORS.put(52, "[KRB_ERR_RESPONSE_TOO_BIG] Response too big for UDP; retry with TCP");
        KRB_ERRORS.put(60, "[KRB_ERR_GENERIC] Generic error (description in e-text)");
        KRB_ERRORS.put(61, "[KRB_ERR_FIELD_TOOLONG] Field is too long for this implementation");
        KRB_ERRORS.put(62, "[KDC_ERROR_CLIENT_NOT_TRUSTED] Reserved for PKINIT");
        KRB_ERRORS.put(63, "[KDC_ERROR_KDC_NOT_TRUSTED] Reserved for PKINIT");
        KRB_ERRORS.put(64, "[KDC_ERROR_INVALID_SIG] Reserved for PKINIT");
        KRB_ERRORS.put(65, "[KDC_ERR_KEY_TOO_WEAK] Reserved for PKINIT");
        KRB_ERRORS.put(66, "[KDC_ERR_CERTIFICATE_MISMATCH] Reserved for PKINIT");
        KRB_ERRORS.put(67, "[KRB_AP_ERR_NO_TGT] No TGT available to validate USER-TO-USER");
        KRB_ERRORS.put(68, "[KDC_ERR_WRONG_REALM] Reserved for future use");
        KRB_ERRORS.put(69, "[KRB_AP_ERR_USER_TO_USER_REQUIRED] Ticket must be for USER-TO-USER");
        KRB_ERRORS.put(70, "[KDC_ERR_CANT_VERIFY_CERTIFICATE] Reserved for PKINIT");
        KRB_ERRORS.put(71, "[KDC_ERR_INVALID_CERTIFICATE] Reserved for PKINIT");
        KRB_ERRORS.put(72, "[KDC_ERR_REVOKED_CERTIFICATE] Reserved for PKINIT");
        KRB_ERRORS.put(73, "[KDC_ERR_REVOCATION_STATUS_UNKNOWN] Reserved for PKINIT");
        KRB_ERRORS.put(74, "[KDC_ERR_REVOCATION_STATUS_UNAVAILABLE] Reserved for PKINIT");
        KRB_ERRORS.put(75, "[KDC_ERR_CLIENT_NAME_MISMATCH] Reserved for PKINIT");
        KRB_ERRORS.put(76, "[KDC_ERR_KDC_NAME_MISMATCH] Reserved for PKINIT");
    }
}
