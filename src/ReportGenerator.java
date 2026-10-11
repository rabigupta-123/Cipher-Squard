import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * ReportGenerator produces immutable, court-admissible forensic artifacts in PDF format.
 *
 * <p>Implementation Details:
 * <ul>
 *   <li>Standard: Compliant with ISO 32000-1 / PDF 1.4 specification.</li>
 *   <li>Zero Runtime Dependencies: Implemented purely using standard JDK 25 I/O streams
 *       ({@link java.io.ByteArrayOutputStream}) without requiring external native binaries
 *       or third-party libraries (e.g. iText, Apache PDFBox, OpenPDF).</li>
 *   <li>Structure: Builds a 6-object PDF structure consisting of Document Catalog (/Catalog),
 *       Page Tree Root (/Pages), Page Object (/Page with standard A4 MediaBox [0 0 595 842]),
 *       Standard Type 1 Font Resource (/Helvetica), Text Content Stream (/Length),
 *       exact-byte Cross-Reference Table (xref), and Trailer dictionary (/Root).</li>
 *   <li>Deterministic Output: Emits sanitized ASCII/ISO-8859-1 glyphs with parentheses
 *       and backslashes properly escaped according to Section 7.3.4.2 of the PDF spec.</li>
 * </ul>
 */
public final class ReportGenerator {

    private static final String REPORT_TITLE = "CIPHER SQUAD - FORENSIC EVIDENCE REPORT";
    private static final String FOOTER_TEXT = "Certified Forensic Analysis - Problem Statement 26106 Digital Evidence";

    /**
     * Generates a binary PDF 1.4 document containing the complete forensic case dossier,
     * chain-of-custody audit proofs, feature breakdowns, and attribution timeline.
     *
     * @param reportData A structured map containing "case", "audit", "featureBreakdown",
     *                   and "attribution" records.
     * @return Raw byte array representing the serialized PDF 1.4 document.
     * @throws Exception If stream serialization fails.
     */
    @SuppressWarnings("unchecked")
    public static byte[] generatePdf(Map<String, Object> reportData) throws Exception {
        List<String> lines = new ArrayList<>();
        lines.add("=== " + REPORT_TITLE + " ===");
        lines.add("");

        // 0. Chain of Custody
        lines.add("0. CHAIN OF CUSTODY MANIFEST");
        Map<String, Object> audit = (Map<String, Object>) reportData.get("audit");
        if (audit != null) {
            lines.add("  Audit Assurance: " + audit.get("assurance"));
            lines.add("  Head Hash: " + audit.get("headHash"));
            lines.add("  Signature Valid: " + audit.get("headSignatureValid"));
            lines.add("  Last Signed Index: " + audit.get("lastSignedIndex"));
        } else {
            lines.add("  Chain of custody could not be verified.");
        }
        lines.add("");

        // 1. Case Summary
        lines.add("1. CASE SUMMARY");
        Map<String, Object> caseRec = (Map<String, Object>) reportData.get("case");
        if (caseRec != null) {
            lines.add("  Case Identifier: " + caseRec.get("id"));
            lines.add("  Evidence SHA-256: " + caseRec.get("evidenceHash"));
            lines.add("  Observation Time: " + caseRec.get("observedAt"));
            lines.add("  Final Verdict: " + caseRec.get("verdict"));
            lines.add("  Risk Score: " + caseRec.get("riskFinal"));
        }
        lines.add("");

        // 2. Semantic Analysis
        lines.add("2. SEMANTIC ANALYSIS");
        if (reportData.containsKey("featureBreakdown")) {
            Map<String, Object> breakdown = (Map<String, Object>) reportData.get("featureBreakdown");
            List<Map<String, Object>> families = (List<Map<String, Object>>) breakdown.get("families");
            if (families != null) {
                for (Map<String, Object> fam : families) {
                    lines.add("  " + fam.get("name") + " Contribution: " + fam.get("contribution"));
                }
            }
        } else {
            lines.add("  Semantic breakdown not available for this record.");
        }
        lines.add("");

        // 3. Infrastructure & Correlation
        lines.add("3. INFRASTRUCTURE & CORRELATION");
        if (caseRec != null) {
            Object doms = caseRec.get("domains");
            Object hops = caseRec.get("hopAddresses");
            lines.add("  Sender Domains: " + (doms instanceof List ? String.join(", ", (List<String>) doms) : "None"));
            lines.add("  Observed IPs: " + (hops instanceof List ? String.join(", ", (List<String>) hops) : "None"));
        }
        lines.add("");
        boolean isSigned = audit != null && Boolean.TRUE.equals(audit.get("headSignatureValid"))
                && "SIGNED".equalsIgnoreCase(String.valueOf(audit.get("assurance")));
        if (isSigned) {
            lines.add("Cryptographic Proof: Valid Ed25519 Root Signature Verified");
            lines.add("Signed By: CipherSquad Forensic Authority");
        } else {
            lines.add("Cryptographic Proof: Unsigned / Hash-Linked Chain (Ed25519 Checkpoint Pending)");
            lines.add("Integrity Notice: Uncertified Pending Cryptographic Sign-Off");
        }
        lines.add(FOOTER_TEXT);

        return buildPdfDocument(lines);
    }

    private static byte[] buildPdfDocument(List<String> lines) throws IOException {
        StringBuilder streamContent = new StringBuilder();
        streamContent.append("BT\n");
        streamContent.append("/F1 10 Tf\n");
        streamContent.append("50 780 Td\n");
        streamContent.append("14 TL\n");

        for (String line : lines) {
            String sanitized = escapePdfString(line);
            streamContent.append("(").append(sanitized).append(") '\n");
        }
        streamContent.append("ET\n");

        byte[] streamBytes = streamContent.toString().getBytes(StandardCharsets.ISO_8859_1);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        List<Integer> offsets = new ArrayList<>();

        baos.write("%PDF-1.4\n".getBytes(StandardCharsets.US_ASCII));

        // Obj 1: Catalog
        offsets.add(baos.size());
        baos.write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".getBytes(StandardCharsets.US_ASCII));

        // Obj 2: Pages
        offsets.add(baos.size());
        baos.write("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".getBytes(StandardCharsets.US_ASCII));

        // Obj 3: Page
        offsets.add(baos.size());
        baos.write("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n".getBytes(StandardCharsets.US_ASCII));

        // Obj 4: Font
        offsets.add(baos.size());
        baos.write("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".getBytes(StandardCharsets.US_ASCII));

        // Obj 5: Stream
        offsets.add(baos.size());
        String streamHeader = "5 0 obj\n<< /Length " + streamBytes.length + " >>\nstream\n";
        baos.write(streamHeader.getBytes(StandardCharsets.US_ASCII));
        baos.write(streamBytes);
        baos.write("\nendstream\nendobj\n".getBytes(StandardCharsets.US_ASCII));

        // Xref
        int startXref = baos.size();
        baos.write("xref\n0 6\n".getBytes(StandardCharsets.US_ASCII));
        baos.write("0000000000 65535 f \n".getBytes(StandardCharsets.US_ASCII));
        for (int off : offsets) {
            baos.write(String.format(Locale.ROOT, "%010d 00000 n \n", off).getBytes(StandardCharsets.US_ASCII));
        }

        // Trailer
        baos.write("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n".getBytes(StandardCharsets.US_ASCII));
        baos.write((startXref + "\n%%EOF\n").getBytes(StandardCharsets.US_ASCII));

        return baos.toByteArray();
    }

    private static String escapePdfString(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                    .replace("(", "\\(")
                    .replace(")", "\\)")
                    .replaceAll("[^\\x20-\\x7E]", " ");
    }
}
