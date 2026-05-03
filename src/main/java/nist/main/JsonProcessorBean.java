package nist.main;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.faces.context.FacesContext;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpSession;
import nist.Functions.JsonProcessor;
import org.primefaces.event.FileUploadEvent;
import org.primefaces.model.DefaultStreamedContent;
import org.primefaces.model.StreamedContent;
import org.primefaces.model.file.UploadedFile;

import java.io.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * JSF backing bean that handles uploading, processing, and exporting JSON vulnerability data.
 * It supports filtering based on years and keywords and exports results as CSV and ZIP files.
 *
 * @author Aman Utkarsh and Tarun Kumar
 * @version 1.0
 */
@Named("jsonProcessorBean")
@ViewScoped
public class JsonProcessorBean implements Serializable {

    /** Start year used for filtering JSON data by CVE year. */
    private Integer startYear;

    /** End year used for filtering JSON data by CVE year. */
    private Integer endYear;

    /** Start year as string, used in the UI. */
    private String startYearStr;

    /** End year as string, used in the UI. */
    private String endYearStr;

    /** Comma-separated keywords to filter CVE entries. */
    private String keywords;

    /** Log messages accumulated during processing. */
    private String outputLog = "";

    /** List of processed file names. */
    private final List<String> processedFiles = new ArrayList<>();

    /** Flag indicating whether the results dialog should be shown. */
    private boolean showDialog;

    /** Flag indicating if the processing has completed. */
    private boolean processCompleted = false;

    /** Directory used to store temporary output files. */
    private File outputDir;

    /** Latest generated ZIP file containing CSV outputs. */
    private File latestZipFile;

    /** Initializes the bean and prepares the output directory. */
    @PostConstruct
    public void init() {
        try {
            startYearStr = "";
            endYearStr = "";
            HttpSession session = (HttpSession) FacesContext.getCurrentInstance()
                    .getExternalContext().getSession(true);
            String sessionId = session.getId();
            outputDir = new File(System.getProperty("java.io.tmpdir"), "nist-output-" + sessionId);

            if (!outputDir.exists() && !outputDir.mkdirs()) {
                appendLog(getMessage("error.createOutputDir"));
            }
        } catch (Exception e) {
            appendLog(getMessage("error.initBean", e.getMessage()));
        }
    }

    /** Cleans up temporary files created during processing. */
    @PreDestroy
    public void cleanup() {
        if (outputDir != null && outputDir.exists()) {
            for (File file : outputDir.listFiles()) {
                if (file.isFile()) {
                    file.delete();
                }
            }
            outputDir.delete();
        }
    }

    private void convertYearStringsToIntegers() {
        try {
            if (startYearStr != null && !startYearStr.isEmpty()) {
                startYear = Integer.parseInt(startYearStr);
            }
            if (endYearStr != null && !endYearStr.isEmpty()) {
                endYear = Integer.parseInt(endYearStr);
            }
        } catch (NumberFormatException e) {
            appendLog(getMessage("error.invalidYearConversion", e.getMessage()));
        }
    }

    /**
     * Processes uploaded JSON files, filtering and exporting to CSV.
     */
    public void process() {
        convertYearStringsToIntegers();
        processedFiles.clear();
        processCompleted = false;
        showDialog = false;

        try {
            List<String> keyList = parseKeywords();
            File[] jsonFiles = outputDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".json"));

            if (jsonFiles == null || jsonFiles.length == 0) {
                appendLog(getMessage("warn.noJsonFiles", outputDir.getAbsolutePath()));
                return;
            }

            for (File jsonFile : jsonFiles) {
                String name = jsonFile.getName();

                if (!name.equalsIgnoreCase("Total.json")) {
                    try {
                        String[] parts = name.split("-");
                        if (parts.length < 3) {
                            appendLog(getMessage("warn.unexpectedFileName", name));
                            continue;
                        }

                        String yearPart = parts[2].replace(".json", "");
                        int year = Integer.parseInt(yearPart);

                        boolean shouldProcess = false;

                        if (year == 2002 && startYear != null && (startYear == 2001 || startYear == 2002)) {
                            shouldProcess = true;
                        } else if (startYear != null && endYear != null && year >= startYear && year <= endYear) {
                            shouldProcess = true;
                        }

                        if (!shouldProcess) {
                            appendLog(getMessage("warn.omittedByYear", name));
                            continue;
                        }

                    } catch (Exception e) {
                        appendLog(getMessage("warn.invalidYear", name));
                        continue;
                    }
                }

                appendLog(getMessage("info.processingFile", name));
                JsonProcessor processor = new JsonProcessor(jsonFile, keyList);
                String prefix = name.replace(".json", "");

                processor.cveToCSV(new File(outputDir, prefix + "-cve.csv").getAbsolutePath(), true);
                processor.cweToCSV(new File(outputDir, prefix + "-cwe.csv").getAbsolutePath(), true);
                processor.softwareToCSV(new File(outputDir, prefix + "-swProducts.csv").getAbsolutePath(), true);

                appendLog(getMessage("info.processingDone", prefix));
                processedFiles.add(name);
            }

            // Generate merged Total-*.csv from all per-year CSVs
            generateTotalCsvs();

            prepareDownload();
            processCompleted = true;
            showDialog = true;
            appendLog(getMessage("log.completed"));

        } catch (Exception e) {
            appendLog(getMessage("error.processing", e.getMessage()));
        }
    }

    /**
     * Merges all per-year CVE, CWE and swProducts CSV files into three
     * aggregate Total-*.csv files, keeping only one header row at the top.
     */
    private void generateTotalCsvs() {
        try {
            mergeCsvGroup("cve");
            mergeCsvGroup("cwe");
            mergeCsvGroup("swProducts");
            appendLog("Total CSV files generated: Total-cve.csv, Total-cwe.csv, Total-swProducts.csv");
        } catch (IOException e) {
            appendLog("Error generating Total CSVs: " + e.getMessage());
        }
    }

    /**
     * Merges all per-year CSV files of a given type (cve, cwe, swProducts)
     * into a single Total-[type].csv, preserving one shared header.
     *
     * @param type the CSV type suffix to merge
     * @throws IOException if a file cannot be read or written
     */
    private void mergeCsvGroup(String type) throws IOException {
        File[] parts = outputDir.listFiles((dir, name) ->
                name.endsWith("-" + type + ".csv") && !name.startsWith("Total-"));
        if (parts == null || parts.length == 0) return;

        // Sort by filename so years are in order
        java.util.Arrays.sort(parts);

        File totalFile = new File(outputDir, "Total-" + type + ".csv");
        if (totalFile.exists()) totalFile.delete();

        boolean headerWritten = false;
        try (BufferedWriter writer = new BufferedWriter(
                new java.io.OutputStreamWriter(new FileOutputStream(totalFile), java.nio.charset.StandardCharsets.UTF_8))) {

            for (File part : parts) {
                try (BufferedReader reader = new BufferedReader(
                        new java.io.InputStreamReader(new FileInputStream(part), java.nio.charset.StandardCharsets.UTF_8))) {

                    String line;
                    boolean firstLine = true;
                    while ((line = reader.readLine()) != null) {
                        if (firstLine) {
                            firstLine = false;
                            if (!headerWritten) {
                                // Write header only from the first file
                                writer.write(line);
                                writer.newLine();
                                headerWritten = true;
                            }
                            // Skip header lines from subsequent files
                            continue;
                        }
                        // Skip the TOTAL summary lines at the end of each per-year file
                        if (line.startsWith("TOTAL ") || line.isEmpty()) continue;
                        writer.write(line);
                        writer.newLine();
                    }
                }
            }
        }
    }

    /**
     * Generates a ZIP file from the generated CSV outputs.
     */
    public void prepareDownload() {
        try {
            File zip = File.createTempFile("nist-output-", ".zip", outputDir);
            try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zip))) {
                File[] csvFiles = outputDir.listFiles((dir, name) -> name.endsWith(".csv"));
                if (csvFiles != null) {
                    for (File file : csvFiles) {
                        try (FileInputStream fis = new FileInputStream(file)) {
                            zos.putNextEntry(new ZipEntry(file.getName()));
                            byte[] buffer = new byte[1024];
                            int len;
                            while ((len = fis.read(buffer)) > 0) {
                                zos.write(buffer, 0, len);
                            }
                            zos.closeEntry();
                        }
                    }
                }
            }
            this.latestZipFile = zip;
        } catch (Exception e) {
            appendLog(getMessage("error.zipGeneration", e.getMessage()));
        }
    }

    /**
     * Returns the ZIP file containing processed data for user download.
     *
     * @return a streamed ZIP file containing CSVs
     */
    public StreamedContent getDownloadAllAsZip() {
        try {
            if (latestZipFile == null || !latestZipFile.exists()) {
                appendLog(getMessage("error.zipUnavailable"));
                return null;
            }

            InputStream is = new FileInputStream(latestZipFile);
            return DefaultStreamedContent.builder()
                    .name("nist-output.zip")
                    .contentType("application/zip")
                    .stream(() -> is)
                    .build();

        } catch (Exception e) {
            appendLog(getMessage("error.prepareZip", e.getMessage()));
            return null;
        }
    }

    /**
     * Handles file upload events, storing files if they match criteria.
     *
     * @param event the file upload event from PrimeFaces
     */
    public void handleUpload(FileUploadEvent event) {
        try {
            convertYearStringsToIntegers();

            UploadedFile uploadedFile = event.getFile();
            String fileName = uploadedFile.getFileName();

            if (fileName.equalsIgnoreCase("Total.json")) {
                saveUploadedFile(uploadedFile);
                appendLog(getMessage("info.fileUploaded", fileName));
                return;
            }

            int year = -1;
            try {
                String[] parts = fileName.replace(".json", "").split("-");
                year = Integer.parseInt(parts[parts.length - 1]);
            } catch (Exception e) {
                appendLog(getMessage("warn.invalidYear", fileName));
            }

            if (year != -1 && startYear != null && endYear != null) {
                if (year >= startYear && year <= endYear) {
                    saveUploadedFile(uploadedFile);
                    appendLog(getMessage("info.fileUploaded", fileName));
                } else {
                    appendLog(getMessage("warn.fileYearOutOfRange", fileName));
                }
            } else {
                appendLog(getMessage("warn.invalidFileFormat", fileName));
            }

        } catch (IOException e) {
            appendLog(getMessage("error.uploadFile", e.getMessage()));
        }
    }

    private void saveUploadedFile(UploadedFile uploadedFile) throws IOException {
        File file = new File(outputDir, uploadedFile.getFileName());
        try (InputStream in = uploadedFile.getInputStream();
             FileOutputStream fos = new FileOutputStream(file)) {
            byte[] buffer = new byte[65536]; // 64 KB chunks — never loads full file into RAM
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
        }
    }

    /**
     * Clears all fields and resets the bean to its initial state.
     */
    public void clear() {
        startYear = null;
        endYear = null;
        startYearStr = "";
        endYearStr = "";
        keywords = null;
        outputLog = "";
        processedFiles.clear();
        showDialog = false;
        processCompleted = false;
        latestZipFile = null;
        appendLog(getMessage("log.reset"));
    }

    // Getters and Setters with Javadoc

    /** @return true if dialog should be shown */
    public boolean isShowDialog() { return showDialog; }

    /** @return true if processing is complete */
    public boolean isProcessCompleted() { return processCompleted; }

    /** @return list of processed filenames */
    public List<String> getProcessedFiles() { return processedFiles; }

    /** @return selected start year */
    public Integer getStartYear() { return startYear; }

    /** @param startYear the start year to set */
    public void setStartYear(Integer startYear) { this.startYear = startYear; }

    /** @return selected end year */
    public Integer getEndYear() { return endYear; }

    /** @param endYear the end year to set */
    public void setEndYear(Integer endYear) { this.endYear = endYear; }

    /** @return input keyword string */
    public String getKeywords() { return keywords; }

    /** @param keywords the keyword string to set */
    public void setKeywords(String keywords) { this.keywords = keywords; }

    /** @return current output log */
    public String getOutputLog() { return outputLog; }

    /** @param outputLog log text to set */
    public void setOutputLog(String outputLog) { this.outputLog = outputLog; }

    /** @param showDialog flag to display dialog */
    public void setShowDialog(boolean showDialog) { this.showDialog = showDialog; }

    /** @return start year as string */
    public String getStartYearStr() { return startYearStr; }

    /** @param startYearStr start year input string */
    public void setStartYearStr(String startYearStr) { this.startYearStr = startYearStr; }

    /** @return end year as string */
    public String getEndYearStr() { return endYearStr; }

    /** @param endYearStr end year input string */
    public void setEndYearStr(String endYearStr) { this.endYearStr = endYearStr; }

    private void appendLog(String msg) {
        outputLog = (outputLog == null ? "" : outputLog + "\n") + msg;
    }

    private List<String> parseKeywords() {
        List<String> list = new ArrayList<>();
        if (keywords != null) {
            for (String kw : keywords.split(",")) {
                String trimmed = kw.trim();
                if (!trimmed.isEmpty()) {
                    list.add(trimmed.toUpperCase());
                }
            }
        }
        return list;
    }

    private String getMessage(String key, Object... params) {
        FacesContext context = FacesContext.getCurrentInstance();
        ResourceBundle bundle = ResourceBundle.getBundle("messages", context.getViewRoot().getLocale());
        String pattern = bundle.getString(key);
        return java.text.MessageFormat.format(pattern, params);
    }
}
