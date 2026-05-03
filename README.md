# NistJson: Open-Source Tool for JSON Processing and Software Vulnerabilities Analysis Based on NIST NVD
![NistJson Tool](TutorialImgs/NistJson1.PNG)

## Description
NistJson is a web-based Java application meticulously designed for the efficient processing, analysis, and export of Common Vulnerabilities and Exposures (CVE) data released by the National Vulnerability Database (NVD). Unlike command-line utilities or scripts, NistJson incorporates an interactive, multilingual graphical user interface (GUI), designed with Jakarta EE and PrimeFaces, providing an accessible and reproducible environment for software vulnerability analysis.

The application allows users to filter CVEs by year and keyword, correlate them with Common Weakness Enumeration (CWE) categories, and export the resulting datasets in Comma-Separated Values ​​(CSV) format. Due to its keyword filtering capabilities, it can be applied to any branch of knowledge, including eHealth security, DevSecOps processes, and academic research that requires comprehensive vulnerability assessments and reproducibility.

## Key Features

- **Intuitive Web Interface with Flexible Configuration**: Tailored for both proficient developers and individuals lacking technical expertise, NistJson features a contemporary web interface constructed utilizing JSF and PrimeFaces. Users possess the capability to directly modify parameters such as temporal ranges, keywords, and output language through the interface.

- **Internationalization and Multilingual UI**: Incorporates inherent support for English, Spanish, French, Portuguese, and German. Users have the ability to transition between languages during runtime via a session-aware user interface component, with language files administered through JSF resource bundles.

- **Multi-file JSON Upload & High-Performance Parsing**: Facilitates the batch upload of JSON files (in SCAP format) sourced from the National Vulnerability Database (NVD), thus enabling scalable and efficient parsing of extensive datasets through the utilization of the Jackson library.

- **Advanced Filtering and Data Enrichment**: Offers comprehensive parameterizable filtering predicated on keywords, year ranges, and additional criteria. Enhances vulnerability entries with enriched metadata, including CVSS metrics, CWE classifications, and relevance concerning health.

- **Vulnerability Classification and Metrics**: Categorizes CVEs into CWE classifications and computes sophisticated statistics encompassing average scores, software presence, and health impact metrics pertinent to each category.

- **Export to CSV and ZIP**: Produces downloadable CSV files encompassing CVE entries, CWE summaries, and affected software products. All outputs are systematically consolidated into a ZIP archive for the sake of user convenience during download.

- **Research Reproducibility and Output Integrity**: Guarantees consistency in data processing by standardizing input formats and execution parameters, thereby facilitating reproducibility in both academic and professional research endeavors.

- **Modular and Extensible Architecture**: Engineered with rigorous object-oriented principles and a modular framework, permitting the seamless integration of new filters, views, or export formats with minimal disruption to the existing codebase.

- **Cross-platform and Standards-based Deployment**: Constructed utilizing Java 17 and Jakarta EE 10, the application is encapsulated as a WAR file and is deployable on any compliant application server (e.g., Payara, WildFly) across various operating systems including Windows, Linux, or macOS.

## Installation of <a name="_hlk187925083"></a>NetBeans Ide 8.0.2

1. Run the Apache NetBeans Ide 25 installer and press the "Next" button:
   
<div align="center">
  <img src="TutorialImgs/Netbeans1.png" alt="NetBeans" />
</div>

2. Accept the Licence Agreement and click on “Next” button:
<div align="center">
  <img src="TutorialImgs/Netbeans2.png" alt="NetBeans2" />
</div>

 3. Select the installation path and click on Next button 
    
<div align="center">
  <img src="TutorialImgs/Netbeans3.png" alt="NetBeans3" />
</div>
  
 4. Click on install button 
    
<div align="center">
  <img src="TutorialImgs/Netbeans4.png" alt="NetBeans4" />
</div>
 
 5. Wait until the installation process is completed
    
<div align="center">
  <img src="TutorialImgs/Netbeans5.png" alt="NetBeans5" />
</div>
 
 6. Click on the Finish button 
    
<div align="center">
  <img src="TutorialImgs/Netbeans6.png" alt="NetBeans6" />
</div>

## Preparing java project

 1. Select the directory to which the repository will be cloned:  
    
<div align="center">
  <img src="TutorialImgs/Netbeans7.png" alt="NetBeans7" />
</div>
    
 2. Run the command git clone https://github.com/cmejia5486/NistJsonTool.git
    
<div align="center">
  <img src="TutorialImgs/Netbeans8.png" alt="NetBeans8" />
</div> 

 3. Visit the NIST NVD URL https://nvd.nist.gov/vuln/data-feeds, download the data feeds in JSON format, and place them in an accessible directory for later upload to the web application. 
    
<div align="center">
  <img src="TutorialImgs/Netbeans9.png" alt="NetBeans9" />
</div> 

 4. Open the project in the previously installed Apache NetBeans Ide 25 and click on clean and build option.
    
<div align="center">
  <img src="TutorialImgs/Netbeans10.png" alt="NetBeans10" />
</div> 

 5. Go to the services tab, in the servers option select "Add Server...".
    
<div align="center">
  <img src="TutorialImgs/Netbeans11.png" alt="NetBeans11" />
</div> 

 6. Select "Payara Server" and click next.
    
<div align="center">
  <img src="TutorialImgs/Netbeans12.png" alt="NetBeans12" />
</div> 

7. Select option 6.2025.4 and click the "Download Now..." button.
    
<div align="center">
  <img src="TutorialImgs/Netbeans13.png" alt="NetBeans13" />
</div> 

8. Once the necessary files have been downloaded, click the "Next" button.
    
<div align="center">
  <img src="TutorialImgs/Netbeans14.png" alt="NetBeans14" />
</div> 

9. Review the settings for the Payara server and click the "Finish" button.
    
<div align="center">
  <img src="TutorialImgs/Netbeans15.png" alt="NetBeans15" />
</div> 

10. Right click on Payara Server and press the "Start" button..
    
<div align="center">
  <img src="TutorialImgs/Netbeans16.png" alt="NetBeans16" />
</div> 

11. Once Payara server is deployed, visit the address http://localhost:4848, to access the administration console.
    
<div align="center">
  <img src="TutorialImgs/Netbeans17.png" alt="NetBeans17" />
</div> 

12. Click on the application option to manage the deployed applications.
    
<div align="center">
  <img src="TutorialImgs/Netbeans18.png" alt="NetBeans18" />
</div> 

13. Click the "deploy" button, select the *.war file of the application you want to deploy, and click "ok.".
    
<div align="center">
  <img src="TutorialImgs/Netbeans19.png" alt="NetBeans19" />
</div> 

15. The name NistJson will be presented as a list of applications deployed on the server, then click on "Launch" buttom.
    
<div align="center">
  <img src="TutorialImgs/Netbeans20.png" alt="NetBeans20" />
</div> 

## 6.	Running the tool

1. Click on the first server link.
    
<div align="center">
  <img src="TutorialImgs/Netbeans21.png" alt="NetBeans21" />
</div> 

2. You will be redirected to the index.xhtml, the main page of the tool presented in this project.
    
<div align="center">
  <img src="TutorialImgs/Netbeans22.png" alt="NetBeans21" />
</div> 

3. In the upper right corner, you'll find a language selector to adjust the interface for better user experience and usability.
    
<div align="center">
  <img src="TutorialImgs/Netbeans22.png" alt="NetBeans22" />
</div> 

4. In the input parameters section, you can enter the start year, end year, and keywords that will be used as search criteria, separated by commas, to process the entered JSON files.
    
<div align="center">
  <img src="TutorialImgs/Netbeans23.png" alt="NetBeans23" />
</div> 

5. The "Upload JSON Files" section will allow you to upload JSON files to the server for processing according to the years entered in the previous section, using the "Select files" button.
    
<div align="center">
  <img src="TutorialImgs/Netbeans24.png" alt="NetBeans24" />
</div> 

6. By clicking the "Process JSON" button, the JSON files uploaded to the server will be processed according to the start year, end year, and the keywords entered for the purpose.
    
<div align="center">
  <img src="TutorialImgs/Netbeans25.png" alt="NetBeans25" />
</div> 

7. Details of the files processed or any errors that occurred during execution will be displayed in the "Process Log" section. This section will inform you when the application has completed processing.
    
<div align="center">
  <img src="TutorialImgs/Netbeans26.png" alt="NetBeans26" />
</div> 

8. The "Download CSVs" button allows you to download, in a consolidated manner and in *zip format, the vulnerabilities, software products, and associated CWE categories according to the time interval and previously defined keywords.
    
<div align="center">
  <img src="TutorialImgs/Netbeans27.png" alt="NetBeans27" />
</div> 

## Demo
[Demo video](https://youtu.be/Li2Ww7ov4c0)

## Technical Documentation Manual
[JavaDoc](target/apidocs/index.html)

## **License:**
This project is licensed under the GNU General Public License Version 3 - see the [LICENSE](https://github.com/cmejia5486/NistJsonTool/blob/main/LICENSE) file for details. 

## **Contact:**
**Carlos M. Mejía-Granda** 

- E-mail: <carlosmichael.mejiag@um.es>
- LinkedIn: [Carlos Mejía Granda](https://www.linkedin.com/in/carlos-mej%C3%ADa-granda-70239910a/).

## **Acknowledgements**

We would like to express our gratitude to the National Institute of Standards and Technology (NIST) National Vulnerability Database (NVD) for providing their data feeds in JSON format, which have been invaluable in our experiments and are included as data samples in this repository.
