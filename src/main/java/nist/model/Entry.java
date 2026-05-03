package nist.model;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Represents an <i>Entry</i> for a vulnerability in the NIST data feed. Each
 * entry contains detailed information about a specific vulnerability, including
 * its severity, impact, exploitability, and affected software.
 *
 * <p>
 * This class supports operations for tracking, comparing, and describing
 * vulnerability data entries.</p>
 *
 * @author Aman Utkarsh and Tarun Kumar
 * @version 1.0
 * @since 2024-05-01
 */
public class Entry {

    private String id;
    private String summary;
    private double score;
    private String attackVector;
    private String accessComplexity;
    private String authentication;
    private String confidentiality;
    private String integrity;
    private String availability;
    private String severity;
    private double exploitability;
    private double impact;
    private Integer obtainAllPrivilege;
    private Integer obtainUserPrivilege;
    private Integer obtainOtherPrivilege;
    private Integer userInteractionRequired;
    private Integer rankingForHealth;
    private String category;
    private final List<String> vulnerableSoftware;

    /**
     * Default constructor initializing an empty list of vulnerable software.
     */
    public Entry() {
        this.vulnerableSoftware = new CopyOnWriteArrayList<>();
    }

    /**
     * Constructs an {@code Entry} with a specified ID and health ranking.
     *
     * @param id the unique identifier for the vulnerability
     * @param ranking the ranking of the vulnerability for health-related
     * systems
     */
    public Entry(String id, Integer ranking) {
        this();
        this.id = id;
        this.rankingForHealth = ranking;
    }

    /**
     * Returns the unique identifier of the vulnerability.
     *
     * @return the vulnerability ID
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the unique identifier of the vulnerability.
     *
     * @param id the vulnerability ID
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Returns a brief summary of the vulnerability.
     *
     * @return the summary
     */
    public String getSummary() {
        return summary;
    }

    /**
     * Sets the summary of the vulnerability.
     *
     * @param summary the summary
     */
    public void setSummary(String summary) {
        this.summary = summary;
    }

    /**
     * Returns the CVSS score of the vulnerability.
     *
     * @return the score
     */
    public double getScore() {
        return score;
    }

    /**
     * Sets the CVSS score of the vulnerability.
     *
     * @param score the score
     */
    public void setScore(double score) {
        this.score = score;
    }

    /**
     * Returns the severity level of the vulnerability.
     *
     * @return the severity
     */
    public String getSeverity() {
        return severity;
    }

    /**
     * Sets the severity level of the vulnerability.
     *
     * @param severity the severity
     */
    public void setSeverity(String severity) {
        this.severity = severity;
    }

    /**
     * Returns the exploitability score.
     *
     * @return the exploitability score
     */
    public double getExploitability() {
        return exploitability;
    }

    /**
     * Sets the exploitability score.
     *
     * @param exploitability the exploitability score
     */
    public void setExploitability(double exploitability) {
        this.exploitability = exploitability;
    }

    /**
     * Returns the impact score.
     *
     * @return the impact score
     */
    public double getImpact() {
        return impact;
    }

    /**
     * Sets the impact score.
     *
     * @param impact the impact score
     */
    public void setImpact(double impact) {
        this.impact = impact;
    }

    /**
     * Returns the flag indicating if the vulnerability can obtain all
     * privileges.
     *
     * @return the flag
     */
    public Integer getObtainAllPrivilege() {
        return obtainAllPrivilege;
    }

    /**
     * Sets the flag indicating if the vulnerability can obtain all privileges.
     *
     * @param obtainAllPrivilege the flag
     */
    public void setObtainAllPrivilege(Integer obtainAllPrivilege) {
        this.obtainAllPrivilege = obtainAllPrivilege;
    }

    /**
     * Returns the flag indicating if the vulnerability can obtain user
     * privilege.
     *
     * @return the flag
     */
    public Integer getObtainUserPrivilege() {
        return obtainUserPrivilege;
    }

    /**
     * Sets the flag indicating if the vulnerability can obtain user privilege.
     *
     * @param obtainUserPrivilege the flag
     */
    public void setObtainUserPrivilege(Integer obtainUserPrivilege) {
        this.obtainUserPrivilege = obtainUserPrivilege;
    }

    /**
     * Returns the flag indicating if the vulnerability can obtain other
     * privileges.
     *
     * @return the flag
     */
    public Integer getObtainOtherPrivilege() {
        return obtainOtherPrivilege;
    }

    /**
     * Sets the flag indicating if the vulnerability can obtain other
     * privileges.
     *
     * @param obtainOtherPrivilege the flag
     */
    public void setObtainOtherPrivilege(Integer obtainOtherPrivilege) {
        this.obtainOtherPrivilege = obtainOtherPrivilege;
    }

    /**
     * Returns the flag indicating if user interaction is required.
     *
     * @return the flag
     */
    public Integer getUserInteractionRequired() {
        return userInteractionRequired;
    }

    /**
     * Sets the flag indicating if user interaction is required.
     *
     * @param userInteractionRequired the flag
     */
    public void setUserInteractionRequired(Integer userInteractionRequired) {
        this.userInteractionRequired = userInteractionRequired;
    }

    /**
     * Returns the ranking for health-related systems.
     *
     * @return the health ranking
     */
    public Integer getRankingForHealth() {
        return rankingForHealth;
    }

    /**
     * Sets the ranking for health-related systems.
     *
     * @param rankingForHealth the health ranking
     */
    public void setRankingForHealth(Integer rankingForHealth) {
        this.rankingForHealth = rankingForHealth;
    }

    /**
     * Returns the attack vector.
     *
     * @return the attack vector
     */
    public String getAttackVector() {
        return attackVector;
    }

    /**
     * Sets the attack vector.
     *
     * @param attackVector the attack vector
     */
    public void setAttackVector(String attackVector) {
        this.attackVector = attackVector;
    }

    /**
     * Returns the access complexity.
     *
     * @return the access complexity
     */
    public String getAccessComplexity() {
        return accessComplexity;
    }

    /**
     * Sets the access complexity.
     *
     * @param accessComplexity the access complexity
     */
    public void setAccessComplexity(String accessComplexity) {
        this.accessComplexity = accessComplexity;
    }

    /**
     * Returns the authentication required.
     *
     * @return the authentication
     */
    public String getAuthentication() {
        return authentication;
    }

    /**
     * Sets the authentication required.
     *
     * @param authentication the authentication
     */
    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    /**
     * Returns the confidentiality impact.
     *
     * @return the confidentiality
     */
    public String getConfidentiality() {
        return confidentiality;
    }

    /**
     * Sets the confidentiality impact.
     *
     * @param confidentiality the confidentiality
     */
    public void setConfidentiality(String confidentiality) {
        this.confidentiality = confidentiality;
    }

    /**
     * Returns the integrity impact.
     *
     * @return the integrity
     */
    public String getIntegrity() {
        return integrity;
    }

    /**
     * Sets the integrity impact.
     *
     * @param integrity the integrity
     */
    public void setIntegrity(String integrity) {
        this.integrity = integrity;
    }

    /**
     * Returns the availability impact.
     *
     * @return the availability
     */
    public String getAvailability() {
        return availability;
    }

    /**
     * Sets the availability impact.
     *
     * @param availability the availability
     */
    public void setAvailability(String availability) {
        this.availability = availability;
    }

    /**
     * Returns the CWE category of the vulnerability.
     *
     * @return the category
     */
    public String getCategory() {
        return category;
    }

    /**
     * Sets the CWE category of the vulnerability.
     *
     * @param category the category
     */
    public void setCategory(String category) {
        this.category = category;
    }

    /**
     * Returns an unmodifiable list of vulnerable software.
     *
     * @return list of vulnerable software
     */
    public List<String> getVulnerableSoftware() {
        return Collections.unmodifiableList(vulnerableSoftware);
    }

    /**
     * Replaces the current vulnerable software list with a new one.
     *
     * @param softwareList list of vulnerable software
     */
    public void setVulnerableSoftware(List<String> softwareList) {
        this.vulnerableSoftware.clear();
        if (softwareList != null) {
            this.vulnerableSoftware.addAll(softwareList);
        }
    }

    /**
     * Returns the number of affected software products.
     *
     * @return the size of the vulnerable software list
     */
    public int countVulnerableSoftware() {
        return vulnerableSoftware.size();
    }

    /**
     * Checks equality based on the ID field.
     *
     * @param obj the object to compare
     * @return true if equal, false otherwise
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Entry entry = (Entry) obj;
        return Objects.equals(id, entry.id);
    }

    /**
     * Returns a hash code based on the ID field.
     *
     * @return hash code
     */
    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    /**
     * Returns a string representation of the entry.
     *
     * @return the string representation
     */
    @Override
    public String toString() {
        return "Entry{"
                + "id='" + id + '\''
                + ", summary='" + summary + '\''
                + ", score=" + score
                + ", attackVector='" + attackVector + '\''
                + ", accessComplexity='" + accessComplexity + '\''
                + ", authentication='" + authentication + '\''
                + ", confidentiality='" + confidentiality + '\''
                + ", integrity='" + integrity + '\''
                + ", availability='" + availability + '\''
                + ", severity='" + severity + '\''
                + ", exploitability=" + exploitability
                + ", impact=" + impact
                + ", rankingForHealth=" + rankingForHealth
                + ", category='" + category + '\''
                + ", vulnerableSoftware=" + vulnerableSoftware
                + '}';
    }
}
