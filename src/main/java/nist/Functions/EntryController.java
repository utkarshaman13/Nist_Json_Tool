package nist.Functions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import nist.Utility.Functions;
import nist.model.Entry;

/**
 * Controller responsible for processing and mapping JSON vulnerability data
 * into {@link Entry} objects. This class filters entries based on exclusion
 * lists and health rankings.
 *
 * <p>
 * Uses Jackson for JSON parsing and provides a structured approach to
 * determining whether a vulnerability entry is relevant based on predefined
 * criteria.</p>
 *
 * <p>
 * Exclusion data and health metrics are loaded from internal resources upon
 * instantiation.</p>
 *
 * @author Aman Utkarsh and Tarun Kumar
 * @version 1.0
 * @since 2024-05-01
 */
public class EntryController {

    /**
     * The currently processed entry.
     */
    private Entry entry;
    /**
     * Temporary description extracted from JSON.
     */
    private String descriptionTmp;
    /**
     * Temporary summary extracted from JSON.
     */
    private String summaryTmp;
    /**
     * Temporary vulnerability ID extracted from JSON.
     */
    private String IdVulnerabilityTmp;
    /**
     * List of vulnerabilities to exclude.
     */
    private List<String> exclusions;
    /**
     * List of vulnerability entries ranked by health impact.
     */
    private List<Entry> healthValues;
    /**
     * File path for exclusion data.
     */
    private final String exclusionPath;
    /**
     * File path for health metric data.
     */
    private final String healthPath;
    /**
     * Jackson ObjectMapper instance.
     */
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Returns the currently processed {@link Entry}.
     *
     * @return the entry being processed
     */
    public Entry getEntry() {
        return entry;
    }

    /**
     * Sets the current {@link Entry} to be processed.
     *
     * @param entry the entry to set
     */
    public void setEntry(Entry entry) {
        this.entry = entry;
    }

    /**
     * Constructs a new {@code EntryController}, initializing the exclusions and
     * health rankings from their respective resource files.
     */
    public EntryController() {
        exclusions = new ArrayList<>();
        healthValues = new ArrayList<>();
        exclusionPath = "data/Exclusions/exclusions.txt";
        healthPath = "data/Critical/metrics.csv";
        obtainExclusions();
        obtainHealthranking();
    }

    /**
     * Loads the exclusion list from the exclusion file.
     */
    private void obtainExclusions() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("data/Exclusions/exclusions.txt"); BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {

            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(";");
                if (parts.length > 0) {
                    exclusions.add(parts[0]);
                }
            }

        } catch (Exception e) {
            System.out.println("Can't access exclusion file: " + e);
        }
    }

    /**
     * Loads health rankings from the health metric file.
     */
    private void obtainHealthranking() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("data/Critical/metrics.csv"); BufferedReader inputI = new BufferedReader(new InputStreamReader(is))) {

            String readLine;
            int b = -1;
            while ((readLine = inputI.readLine()) != null) {
                b++;
                if (b == 0) {
                    continue; // skip header
                }
                String[] parts = readLine.split(";");
                if (parts.length >= 2) {
                    healthValues.add(new Entry(parts[0], Integer.parseInt(parts[1])));
                }
            }
        } catch (Exception e) {
            System.out.println("Can't access ranking file data/Critical/metrics.csv: " + e);
        }
    }

    /**
     * Verifies if the current vulnerability contains any keyword and is not in
     * the exclusion list.
     *
     * @param keys list of keywords to match
     * @return 1 if valid, otherwise 0
     */
    private Integer verifyKeyAndExclusions(List<String> keys) {
        int response = 0;
        for (String key : keys) {
            if (summaryTmp.toUpperCase().contains(key)) {
                response = 1;
                break;
            }
        }
        for (String exclusion : exclusions) {
            if (exclusion.equals(IdVulnerabilityTmp)) {
                response = 0;
                break;
            }
        }
        return response;
    }

    /**
     * Processes a JSON node to extract vulnerability data into an
     * {@link Entry}.
     *
     * @param obj JSON object node
     * @param keys list of keywords to verify relevance
     * @return a populated {@code Entry} or {@code null} if invalid
     */
    public Entry fill(ObjectNode obj, List<String> keys) {
        if (!getScore(obj).equals(-1D)) {
            summaryTmp = getSummary(obj);
            IdVulnerabilityTmp = getIdVulnerability(obj);
            if (verifyKeyAndExclusions(keys).equals(1)) {
                entry = new Entry();
                entry.setId(IdVulnerabilityTmp);
                entry.setSummary(summaryTmp);
                entry.setScore(getScore(obj));
                entry.setAttackVector(getAccessVector(obj));
                entry.setAccessComplexity(getAccessComplexity(obj));
                entry.setAuthentication(getAuthentication(obj));
                entry.setConfidentiality(getConfidentiality(obj));
                entry.setIntegrity(getIntegrity(obj));
                entry.setAvailability(getAvailability(obj));
                entry.setSeverity(getSeverity(obj));
                entry.setExploitability(getExploitability(obj));
                entry.setImpact(getImpact(obj));
                entry.setObtainAllPrivilege(getObtainAllPrivilege(obj));
                entry.setObtainUserPrivilege(getObtainUserPrivilege(obj));
                entry.setObtainOtherPrivilege(getObtainOtherPrivilege(obj));
                entry.setUserInteractionRequired(getUserInteractionRequired(obj));
                entry.setVulnerableSoftware(getVulnerableSoftware1(entry.getId(), obj));
                entry.setCategory(getCategory(obj));
                entry.setRankingForHealth(getRankingForHealth(IdVulnerabilityTmp));
            } else {
                entry = null;
            }
        } else {
            entry = null;
        }
        return entry;
    }

    // Additional private helper methods are documented individually below
    private String getIdVulnerability(ObjectNode obj) {
        return Functions.CheckString(obj.at("/cve/CVE_data_meta/ID").asText());
    }

    private String getCategory(ObjectNode obj) {
        String response = "";
        ArrayNode problemTypeData = (ArrayNode) obj.at("/cve/problemtype/problemtype_data");
        for (JsonNode data : problemTypeData) {
            ArrayNode description = (ArrayNode) data.get("description");
            if (description != null) {
                for (JsonNode desc : description) {
                    response = desc.get("value").asText();
                }
            }
        }
        return response;
    }

    private String getSummary(ObjectNode obj) {
        ArrayNode descriptionData = (ArrayNode) obj.at("/cve/description/description_data");
        for (JsonNode data : descriptionData) {
            descriptionTmp = data.get("value").asText();
        }
        return Functions.CheckString(descriptionTmp);
    }

    private Double getScore(ObjectNode obj) {
        try {
            JsonNode impact = obj.at("/impact/baseMetricV2");
            if (impact.isMissingNode()) {
                return -1D;
            } else {
                return Functions.fourDecimalsDouble(impact.at("/cvssV2/baseScore").asDouble());
            }
        } catch (Exception e) {
            System.out.println("Error in getScore(): " + e);
            return -1D;
        }
    }

    private String getAccessVector(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/accessVector").asText());
    }

    private String getAccessComplexity(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/accessComplexity").asText());
    }

    private String getAuthentication(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/authentication").asText());
    }

    private String getConfidentiality(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/confidentialityImpact").asText());
    }

    private String getIntegrity(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/integrityImpact").asText());
    }

    private String getAvailability(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/cvssV2/availabilityImpact").asText());
    }

    private Integer getObtainAllPrivilege(ObjectNode obj) {
        return parseBooleanToInteger(obj.at("/impact/baseMetricV2/obtainAllPrivilege").asText());
    }

    private Integer getObtainUserPrivilege(ObjectNode obj) {
        return parseBooleanToInteger(obj.at("/impact/baseMetricV2/obtainUserPrivilege").asText());
    }

    private Integer getObtainOtherPrivilege(ObjectNode obj) {
        return parseBooleanToInteger(obj.at("/impact/baseMetricV2/obtainOtherPrivilege").asText());
    }

    private Integer getUserInteractionRequired(ObjectNode obj) {
        return parseBooleanToInteger(obj.at("/impact/baseMetricV2/userInteractionRequired").asText());
    }

    private Double getExploitability(ObjectNode obj) {
        return Functions.fourDecimalsDouble(obj.at("/impact/baseMetricV2/exploitabilityScore").asDouble());
    }

    private Double getImpact(ObjectNode obj) {
        return Functions.fourDecimalsDouble(obj.at("/impact/baseMetricV2/impactScore").asDouble());
    }

    private String getSeverity(ObjectNode obj) {
        return Functions.CheckString(obj.at("/impact/baseMetricV2/severity").asText());
    }

    private Integer parseBooleanToInteger(String value) {
        return "true".equalsIgnoreCase(value) ? 1 : 0;
    }

    private Integer getRankingForHealth(String id) {
        for (Entry healthValue : healthValues) {
            if (healthValue.getId().equals(id)) {
                return healthValue.getRankingForHealth();
            }
        }
        return -1;
    }

    private String CleanUniqueProducts(String software) {
        if (software.startsWith("cpe:2.3:")) {
            software = software.substring(10);
        }
        software = software.replaceAll(":\\*", "");
        software = software.replaceAll(":-", "");
        String[] parts = software.split(":", 3);

        if (parts.length >= 2) {
            software = parts[0] + ":" + parts[1];
        }

        if (software == null || !software.contains(":")) {
            return software;
        } else {
            parts = software.split(":", 2);
            String vendor = parts[0];
            String product = parts[1];

            int underscoreCount = product.length() - product.replace("_", "").length();

            if (underscoreCount > 1) {
                int firstUnderscore = product.indexOf('_');
                product = product.substring(0, firstUnderscore);
            }
            software = vendor + ":" + product;
            return software;
        }
    }

    private ArrayList<String> getVulnerableSoftware1(String vulne, ObjectNode obj) {
        HashSet<String> response = new HashSet<>();
        ArrayNode nodes = (ArrayNode) obj.at("/configurations/nodes");
        if (nodes != null) {
            for (JsonNode node : nodes) {
                ArrayNode cpeMatch = (ArrayNode) node.get("cpe_match");
                if (cpeMatch != null) {
                    for (JsonNode match : cpeMatch) {
                        response.add(CleanUniqueProducts(match.get("cpe23Uri").asText()));
                    }
                }
                ArrayNode children = (ArrayNode) node.get("children");
                if (children != null) {
                    for (JsonNode child : children) {
                        ArrayNode childCpeMatch = (ArrayNode) child.get("cpe_match");
                        if (childCpeMatch != null) {
                            for (JsonNode match : childCpeMatch) {
                                response.add(CleanUniqueProducts(match.get("cpe23Uri").asText()));
                            }
                        }
                    }
                }
            }
        }
        return new ArrayList<>(response);
    }
}
