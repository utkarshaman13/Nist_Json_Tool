package nist.Functions;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.DoubleAdder;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import nist.Utility.Functions;
import nist.model.Category;
import nist.model.Entry;

/**
 * Controller responsible for managing CWE categories and calculating related
 * statistics. It loads CWE definitions and computes vulnerability metrics.
 *
 * This class reads a list of CWE category definitions from a resource file, and
 * based on a given list of vulnerabilities (CVEs), calculates:
 * <ul>
 * <li>Average CVSS score</li>
 * <li>Presence (proportion within the dataset)</li>
 * <li>Health-related criticality</li>
 * <li>Impact (presence * average score)</li>
 * </ul>
 *
 * @author Aman Utkarsh and Tarun Kumar
 * @version 1.0
 */
public class CategoryController {

    /**
     * List of CWE categories with their summaries.
     */
    private List<Category> summariesCwe;

    /**
     * Path to the resource file that contains the CWE summaries.
     */
    private static final String CWE_SUMMARY_PATH = "data/CweDefinitions/summary.txt";

    /**
     * Constructs a new {@code CategoryController} and initializes the CWE
     * summaries by loading them from the predefined text file.
     */
    public CategoryController() {
        summariesCwe = loadCweSummaries();
    }

    /**
     * Loads CWE definitions from a resource file.
     *
     * @return A list of {@code Category} objects containing CWE IDs and their
     * corresponding descriptions.
     */
    private List<Category> loadCweSummaries() {
        List<Category> summaries = new ArrayList<>();
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(CWE_SUMMARY_PATH); BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {

            summaries = reader.lines()
                    .map(line -> line.split(";"))
                    .filter(parts -> parts.length == 2)
                    .map(parts -> new Category(parts[0], parts[1]))
                    .collect(Collectors.toList());

        } catch (Exception e) {
            System.err.println("Can't access CWE summary file: " + e.getMessage());
        }
        return summaries;
    }

    /**
     * Fills in statistical metrics for a given CWE category, based on the list
     * of CVEs provided.
     *
     * @param cveList The complete list of CVE entries to analyze.
     * @param cweId The CWE category ID to filter and analyze.
     * @return A {@code Category} object populated with relevant metrics (score,
     * impact, etc.).
     */
    public Category fill(List<Entry> cveList, String cweId) {
        // Filters vulnerabilities associated with the given CWE category
        List<Entry> filteredEntries = cveList.parallelStream()
                .filter(entry -> cweId.equals(entry.getCategory()))
                .collect(Collectors.toList());

        // Calculates metrics using parallel streams
        DoubleAdder totalScore = new DoubleAdder();
        AtomicInteger criticalityForHealth = new AtomicInteger();
        filteredEntries.parallelStream().forEach(entry -> {
            totalScore.add(entry.getScore());
            if (entry.getRankingForHealth() == 1) {
                criticalityForHealth.incrementAndGet();
            }
        });

        int totalEntries = filteredEntries.size();
        int totalVulnerabilities = cveList.size();

        // Creates and populates the category object with computed data
        Category category = new Category();
        category.setID(cweId);
        category.setEntries(filteredEntries);
        category.setNumber_of_criticality_for_health_vulnerabilities(criticalityForHealth.get());
        category.setNumber_of_vulnerabilities(totalEntries);
        category.setAverage_score(getAverageScore(totalScore.doubleValue(), totalEntries));
        category.setPresence(getPresence((double) totalEntries, totalVulnerabilities));
        category.setImpact(getImpact(category.getPresence(), category.getAverage_score()));
        category.setSummary(getCweSummary(cweId));

        return category;
    }

    /**
     * Retrieves the summary/description of a given CWE category.
     *
     * @param id The ID of the CWE category.
     * @return The textual summary of the category, or an empty string if not
     * found.
     */
    private String getCweSummary(String id) {
        return summariesCwe.stream()
                .filter(c -> id.equals(c.getID()))
                .map(Category::getSummary)
                .findFirst()
                .orElse("");
    }

    /**
     * Calculates the average CVSS score of a CWE category.
     *
     * @param score The total score of all vulnerabilities in the category.
     * @param cweLength The number of vulnerabilities in the category.
     * @return The average score rounded to 4 decimal places, or 0.0 if none.
     */
    private Double getAverageScore(Double score, int cweLength) {
        return cweLength > 0 ? Functions.fourDecimalsDouble(score / cweLength) : 0.0;
    }

    /**
     * Calculates the presence of a CWE category as a fraction of all analyzed
     * vulnerabilities.
     *
     * @param vulnerables The number of vulnerabilities in the category.
     * @param totalVulnerabilities The total number of vulnerabilities analyzed.
     * @return The presence value (between 0 and 1), rounded to 4 decimal
     * places.
     */
    private Double getPresence(double vulnerables, int totalVulnerabilities) {
        return totalVulnerabilities > 0 ? Functions.fourDecimalsDouble(vulnerables / totalVulnerabilities) : 0.0;
    }

    /**
     * Calculates the impact of a CWE category by multiplying its presence with
     * its average score.
     *
     * @param presence The presence value of the category.
     * @param averageScore The average score of vulnerabilities in the category.
     * @return The impact value, rounded to 4 decimal places.
     */
    private Double getImpact(Double presence, Double averageScore) {
        return Functions.fourDecimalsDouble(presence * averageScore);
    }
}
