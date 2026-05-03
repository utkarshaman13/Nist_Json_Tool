package nist.Functions;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.util.*;

import nist.model.Category;
import nist.model.Entry;
import org.apache.commons.io.FileUtils;

/**
 * Processor responsible for parsing JSON files with CVE vulnerability entries,
 * organizing them into data structures, and exporting the results into CSV
 * files.
 * <p>
 * This class uses {@link EntryController} to process individual entries and
 * {@link CategoryController} to aggregate them by CWE category.
 * </p>
 * <p>
 * Uses Jackson Streaming API to parse large JSON files without loading the
 * entire document into memory, preventing {@link OutOfMemoryError} on large
 * NIST NVD data sets.
 * </p>
 *
 * @author Aman Utkarsh and Tarun Kumar
 * @version 2.0
 * @since 2024-05-01
 */
public class JsonProcessor {

    /**
     * List of keywords used to filter entries.
     */
    private final List<String> keys;
    /**
     * Controller responsible for processing JSON vulnerability entries.
     */
    private final EntryController entryController;
    /**
     * Controller responsible for organizing entries into categories.
     */
    private final CategoryController categoryController;
    /**
     * List of CVE entries extracted from the JSON.
     */
    private final List<Entry> cveEntries;
    /**
     * List of CWE categories derived from the CVE entries.
     */
    private final List<Category> cweCategories;
    /**
     * Hash set for tracking unique CWE identifiers.
     */
    private final Set<String> cwesHash;

    /**
     * Shared Jackson ObjectMapper — reused across streaming operations.
     */
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Constructs a JsonProcessor with the provided file and keyword list.
     * Uses streaming JSON parsing to avoid loading the entire file into memory.
     *
     * @param jsonFile JSON file to parse
     * @param keys     list of keywords for filtering entries
     */
    public JsonProcessor(File jsonFile, List<String> keys) {
        this.keys = keys;
        this.entryController = new EntryController();
        this.categoryController = new CategoryController();
        this.cveEntries = new ArrayList<>();
        this.cweCategories = new ArrayList<>();
        this.cwesHash = new HashSet<>();
        parseJsonStreaming(jsonFile);
        fillCweCategories();
    }

    /**
     * Parses the JSON file using the Jackson Streaming API so only one CVE
     * entry is held in memory at a time.
     * <p>
     * The parser navigates to the {@code CVE_Items} array and reads each
     * element as a self-contained {@link ObjectNode}. This keeps heap usage
     * constant regardless of file size.
     * </p>
     *
     * @param jsonFile input JSON file with CVE data
     */
    private void parseJsonStreaming(File jsonFile) {
        JsonFactory factory = new JsonFactory();
        factory.setCodec(objectMapper);

        try (InputStream fis = new FileInputStream(jsonFile);
             JsonParser parser = factory.createParser(fis)) {

            // Advance to the start of the CVE_Items array
            boolean insideCveItems = false;

            while (parser.nextToken() != null) {
                // Look for the "CVE_Items" field name at the root level
                if (!insideCveItems) {
                    if (parser.currentToken() == JsonToken.FIELD_NAME
                            && "CVE_Items".equals(parser.getCurrentName())) {
                        parser.nextToken(); // move to START_ARRAY
                        if (parser.currentToken() == JsonToken.START_ARRAY) {
                            insideCveItems = true;
                        }
                    }
                    continue;
                }

                // We are inside CVE_Items — each START_OBJECT is one CVE entry
                if (parser.currentToken() == JsonToken.START_OBJECT) {
                    // Read a single CVE entry into an ObjectNode (one entry at a time)
                    ObjectNode node = objectMapper.readTree(parser);
                    Entry entry = entryController.fill(node, keys);
                    if (entry != null) {
                        cwesHash.add(entry.getCategory());
                        cveEntries.add(entry);
                    }
                    // node goes out of scope and is eligible for GC immediately
                } else if (parser.currentToken() == JsonToken.END_ARRAY) {
                    // Finished the CVE_Items array
                    break;
                }
            }

        } catch (IOException e) {
            System.err.println("Error while streaming vulnerabilities: " + e.getMessage());
        }
    }

    /**
     * Fills the list of CWE categories using processed CVE entries.
     */
    private void fillCweCategories() {
        cwesHash.forEach(cwe -> cweCategories.add(categoryController.fill(cveEntries, cwe)));
    }

    /**
     * Exports the list of CVE entries to a CSV file.
     *
     * @param namefile            output CSV file name
     * @param removeFileIfExists  if true, delete existing file before writing
     * @throws IOException if an I/O error occurs
     */
    public void cveToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        Set<String> uniqueProducts = new HashSet<>();
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();

        sb.append("ENTRY;SUMMARY;ACCESS_COMPLEXITY;AUTHENTICATION;CONFIDENTIALITY;INTEGRITY;AVAILABILITY;EXPLOITABILITY;SCORE;PRODUCTS_AFFECTED;PRESENCE;IMPACT;CRITICALITY_FOR_HEALTH;CATEGORY;YEAR\n");

        for (Entry entry : cveEntries) {
            uniqueProducts.addAll(entry.getVulnerableSoftware());

            sb.append(entry.getId()).append(";")
                    .append(entry.getSummary().replace(";", ",")).append(";")
                    .append(entry.getAccessComplexity()).append(";")
                    .append(entry.getAuthentication()).append(";")
                    .append(entry.getConfidentiality()).append(";")
                    .append(entry.getIntegrity()).append(";")
                    .append(entry.getAvailability()).append(";")
                    .append(df.format(entry.getExploitability()).replace(".", ",")).append(";")
                    .append(df.format(entry.getScore()).replace(".", ",")).append(";")
                    .append(entry.getVulnerableSoftware().size()).append(";")
                    .append(df.format((double) entry.getVulnerableSoftware().size() / uniqueProducts.size()).replace(".", ",")).append(";")
                    .append(df.format(entry.getScore() * entry.getVulnerableSoftware().size() / uniqueProducts.size()).replace(".", ",")).append(";");

            String criticality = entry.getRankingForHealth() == 0 ? "NO"
                    : entry.getRankingForHealth() == 1 ? "YES" : "No sabe";
            sb.append(criticality).append(";")
                    .append(entry.getCategory()).append(";")
                    .append(entry.getId().split("-")[1]).append("\n");
        }

        sb.append("\nTOTAL PRODUCTS;").append(uniqueProducts.size());
        writeToFile(namefile, sb.toString(), removeFileIfExists);
    }

    /**
     * Exports CWE category summaries to a CSV file.
     *
     * @param namefile            output CSV file name
     * @param removeFileIfExists  if true, delete existing file before writing
     * @throws IOException if an I/O error occurs
     */
    public void cweToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        DecimalFormat df = new DecimalFormat("#.00000");
        StringBuilder sb = new StringBuilder();
        sb.append("CATEGORY;SUMMARY;NUMBER_OF_VULNERABILITIES;NUMBER_OF_VULNERABILITIES_WITH_CRITICALITY_FOR_HEALTH;AVERAGE_SCORE;PRESENCE;IMPACT;VULNERABLE_SOFTWARE\n");

        int totalVulnerabilities = 0;
        for (Category category : cweCategories) {
            sb.append(category.getID()).append(";")
                    .append(category.getSummary().replace(";", ",")).append(";")
                    .append(category.getNumber_of_vulnerabilities()).append(";")
                    .append(category.getNumber_of_criticality_for_health_vulnerabilities()).append(";")
                    .append(df.format(category.getAverage_score()).replace(".", ",")).append(";")
                    .append(df.format(category.getPresence()).replace(".", ",")).append(";")
                    .append(df.format(category.getImpact()).replace(".", ",")).append(";");

            Set<String> uniqueSoftware = new HashSet<>();
            category.getEntries().forEach(entry -> uniqueSoftware.addAll(entry.getVulnerableSoftware()));
            sb.append(uniqueSoftware.size()).append("\n");

            totalVulnerabilities += category.getNumber_of_vulnerabilities();
        }

        sb.append("\nTOTAL VULNERABILITIES;").append(totalVulnerabilities);
        writeToFile(namefile, sb.toString(), removeFileIfExists);
    }

    /**
     * Exports vulnerable software and their critical vulnerability counts to a
     * CSV file.
     *
     * @param namefile            output CSV file name
     * @param removeFileIfExists  if true, delete existing file before writing
     * @throws IOException if an I/O error occurs
     */
    public void softwareToCSV(String namefile, boolean removeFileIfExists) throws IOException {
        Map<String, Integer> softwareCounts = new HashMap<>();
        Map<String, Integer> criticalCounts = new HashMap<>();

        for (Category category : cweCategories) {
            for (Entry entry : category.getEntries()) {
                for (String software : entry.getVulnerableSoftware()) {
                    softwareCounts.put(software, softwareCounts.getOrDefault(software, 0) + 1);
                    if (entry.getRankingForHealth() == 1) {
                        criticalCounts.put(software, criticalCounts.getOrDefault(software, 0) + 1);
                    }
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("SOFTWARE_PRODUCT;NUMBER_OF_VULNERABILITIES;NUMBER_OF_CRITICAL_VULNERABILITIES\n");
        softwareCounts.forEach((product, count) -> {
            int criticalCount = criticalCounts.getOrDefault(product, 0);
            sb.append(product).append(";").append(count).append(";").append(criticalCount).append("\n");
        });

        writeToFile(namefile, sb.toString(), removeFileIfExists);
    }

    /**
     * Writes content to a file. Optionally removes existing file.
     *
     * @param namefile            file name to write to
     * @param content             the content to write
     * @param removeFileIfExists  if true, deletes existing file before writing
     * @throws IOException if an I/O error occurs
     */
    private void writeToFile(String namefile, String content, boolean removeFileIfExists) throws IOException {
        File file = new File(namefile);
        if (removeFileIfExists && file.exists()) {
            file.delete();
        }
        FileUtils.writeStringToFile(file, content, Charset.forName("UTF-8"), true);
    }
}
