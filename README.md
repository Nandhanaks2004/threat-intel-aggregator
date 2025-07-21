# Threat Intelligence Aggregator

A Python-powered web dashboard that unifies real-time threat intelligence from major sources—**VirusTotal**, **Shodan**, and **AbuseIPDB**—with automated risk assessment, batch scanning, interactive analytics, and secure reporting.

## 🚀 Live Demo

Try the app live:

[**Threat Intel Aggregator App**](https://threat-intel-aggregator-pa9c9rdgja5iqpyh4teskk.streamlit.app/)

https://github.com/Nandhanaks2004/threat-intel-aggregator.git

**Demo credentials:**

- Username: **`Bob`**
- Password: **`testuser123`**

## 🎥 Demo Video

https://drive.google.com/file/d/1_ikJnJ7aV3ZadPw2u2pOVyVSZ1jsnjY4/view?usp=drive_link

## ✨ Features

- **Multi-Source Lookup:** Scan IP addresses, domains, URLs, or file hashes across VirusTotal, Shodan, and AbuseIPDB with one input.
- **Automated Risk Scoring:** Each IOC is automatically assessed and categorized as High, Medium, Low, or Legitimate risk.
- **Batch Scanning:** Drag-and-drop CSV upload for scanning hundreds of IOCs in a single run.
- **Visual Analytics Dashboard:** Interactive charts, timelines, and summary statistics for easy threat triage.
- **PDF Reporting:** Generate and download professional PDF reports of scan results (with email delivery option).
- **API Key Management:** Securely update and manage your API keys directly in the app.
- **Support Panel:** Built-in contact/help section.

## 🟢 Getting Started

## 1. Clone the Repository

`bashgit clone https://github.com/Nandhanaks2004/threat-intel-aggregator.git
cd threat-intel-aggregator`

## 2. Install Dependencies

`bashpip install -r requirements.txt`

## 3. Run the App

`bashstreamlit run streamlit_app.py`

## 4. Configure API Keys

- Option 1: **In the App UI:**
    
    Go to the **Settings** section of the dashboard and add your VirusTotal, Shodan, and AbuseIPDB API keys.
    
- Option 2: **Local secrets file:**
    
    Create **`.streamlit/secrets.toml`** in your project folder:
    
    `text[apikeys]
    VT = "your_virustotal_api_key"
    AbuseIPDB = "your_abuseipdb_api_key"
    Shodan = "your_shodan_api_key"
    
    [credentials]
    users = [
      {username = "admin", password = "admin"}
    ]`
    
- Register for free API keys at:
    - [VirusTotal](https://www.virustotal.com/gui/join-us)
    - [AbuseIPDB](https://www.abuseipdb.com/account/api)
    - [Shodan](https://account.shodan.io/register)

## 🛠 How to Use

- **Single Scan:** Enter an IP, domain, URL, or file hash to run an immediate scan across all integrated platforms.
- **Batch / CSV Scan:** Upload a **`.csv`** file of IOCs for automated enrichment and categorization.
- **Dashboard Analytics:** Review results, filter findings by risk/type, and generate instant charts.
- **PDF Reports:** After scanning, export results as a clean PDF for sharing or compliance needs. Email option available.
- **API Key Settings:** Update your API credentials any time from within the dashboard’s Settings page.

## 🖼 Screenshots

| **Login Page** | **Dashboard View** | **Scan Results** | **Batch Scan** |
| --- | --- | --- | --- |
| login_page.png | Dashboard.png | Results.png | batch_scan.png |

If you encounter API errors (such as rate limits with demo keys), you can enter your **own API keys** directly in the app:

1. Obtain free accounts at:
    - [VirusTotal](https://www.virustotal.com/gui/join-us)
    - [AbuseIPDB](https://www.abuseipdb.com/account/api)
    - [Shodan](https://account.shodan.io/register)
2. Click **Settings & Info** in the sidebar.
3. Enter your new API keys in the provided fields.
4. Click “Save Settings”; all future scans will use your keys.

> For Streamlit Cloud deploys: You can also set keys securely via the app’s Settings > Secrets.Learn more: Streamlit secrets management
> 

## 🤔 FAQ & Troubleshooting

- **Invalid login?** Use the demo credentials above, or check your **`.streamlit/secrets.toml`** file.
- **API errors or limited results?** Use your own API keys in Settings to bypass public rate limits.
- **Security:** No API keys are stored or committed; secrets are managed via environment/config only.
- **Issues/support:** Open a GitHub issue or contact [[support@threatintel.com](mailto:support@threatintel.com)].

## 📚 Documentation

- [Detailed README PDF](https://www.perplexity.ai/search/docs/README.pdf) — walkthrough, screenshots, and advanced usage.

## 📝 Conclusion

Thank you for exploring the Threat Intel Aggregator!

This tool is designed to help security analysts rapidly investigate IOCs, visualize risks, and produce actionable reports. 

Happy scanning! 🛡️
