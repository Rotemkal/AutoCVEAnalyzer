import sqlite3, os
from datetime import datetime
from gpt_analyzer import analyze_cve_with_gpt
from nvd_client import fetch_cve_details
import re
from dotenv import load_dotenv

load_dotenv()

def init_db():
    """Initialize database with essential fields only"""
    conn = sqlite3.connect('autocve.db')
    cursor = conn.cursor()
    
    cursor.execute('DROP TABLE IF EXISTS vulnerabilities')
    cursor.execute('''CREATE TABLE vulnerabilities (
        id INTEGER PRIMARY KEY, 
        cve_id TEXT UNIQUE, 
        description TEXT, 
        severity TEXT, 
        date_added TEXT, 
        relevance TEXT,
        cvss_score REAL, 
        attack_vector TEXT, 
        published_date TEXT, 
        vendor TEXT)''')
    
    conn.commit()
    conn.close()

def show_header():
    """Display application header"""
    # Clean screen - according to os type
    os.system('cls' if os.name == 'nt' else 'clear')
    # Print main menu
    print("╔" + "═" * 70 + "╗")
    print("║" + " " * 20 + "🚗 AutoCVE Analyzer" + " " * 31 + "║")
    print("║" + " " * 17 + "CVE Intelligence for Vehicles" + " " * 24 + "║")
    print("╠" + "═" * 70 + "╣")
    print("║                                                                      ║")
    print("║  1. 📝 Add new CVE                                                   ║")
    print("║  2. 📋 List all CVEs                                                 ║") 
    print("║  3. 🚗 Automotive CVEs only                                          ║")
    print("║  4. 🚪 Exit                                                          ║")
    print("║                                                                      ║")
    print("╚" + "═" * 70 + "╝")

def add_cve():
    """Add new CVE to database"""
    print("\n╔" + "═" * 60 + "╗")
    print("║" + " " * 20 + "📝 Adding New CVE" + " " * 23 + "║")
    print("╚" + "═" * 60 + "╝")
    
    while True:
        cve_id = input("\n🔍 Enter CVE ID: ").strip().upper()

        if re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id):
            break
        print("⚠️ Invalid CVE format. Try again.")
    
    print(f"\n⏳ Fetching details for {cve_id}...")
    
    # Fetch CVE data
    data = fetch_cve_details(cve_id)
    if data:
        description = data['description']
        vendor = data['vendor']
        cvss_score = data['cvss_score']
        attack_vector = data['attack_vector']
        published_date = data['published_date']
        print("✅ Data retrieved successfully")
    else:
        print("No data found in NVD")
        description = input("📄 Enter description manually: ")
        vendor, cvss_score, attack_vector, published_date = "Unknown", None, "Unknown", "Unknown"
    
    # Analyze with GPT
    print("\n🤖 Analyzing with GPT...")
    severity, relevance = analyze_cve_with_gpt(cve_id, description)
    
    # Show results
    show_analysis_results(vendor, severity, cvss_score, attack_vector, published_date, relevance)
    
    # Check if user wants to add non-automotive CVE
    if relevance.lower() == 'no':
        print("\n This CVE is NOT automotive relevant")
        if input("❓ Add anyway? (y/n): ").lower() != 'y':
            print("❌ CVE not added")
            return
    
    save_cve_to_db(cve_id, description, severity, relevance, cvss_score, attack_vector, published_date, vendor)

def show_analysis_results(vendor, severity, cvss_score, attack_vector, published_date, relevance):
    """Display analysis results in a beautiful format"""
    print("\n╔" + "═" * 60 + "╗")
    print("║" + " " * 20 + "📊 Analysis Results" + " " * 21 + "║")
    print("╠" + "═" * 60 + "╣")
    print(f"║  Vendor: {vendor:<49} ║")
    print(f"║  Severity: {severity:<47} ║")
    print(f"║  CVSS Score: {str(cvss_score) if cvss_score else 'N/A':<45} ║")
    print(f"║  Attack Vector: {attack_vector:<42} ║")
    print(f"║  Published: {published_date:<46} ║")
    print(f"║  Automotive Relevant (gpt analysis): {relevance:<21} ║")
    print("╚" + "═" * 60 + "╝")

def save_cve_to_db(cve_id, description, severity, relevance, cvss_score, attack_vector, published_date, vendor):
    """Save CVE to database"""
    try:
        conn = sqlite3.connect('autocve.db')
        conn.execute('''INSERT INTO vulnerabilities VALUES (NULL,?,?,?,?,?,?,?,?,?)''',
                    (cve_id, description, severity, datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
                     relevance, cvss_score, attack_vector, published_date, vendor))
        conn.commit()
        print(f"✅ {cve_id} added to database!")
    except sqlite3.IntegrityError:
        print("CVE already exists in database")
    finally:
        conn.close()

def list_all_cves():
    """Display all CVEs in database"""
    print("\n╔" + "═" * 75 + "╗")
    print("║" + " " * 25 + "📋 All CVEs in Database" + " " * 27 + "║")
    print("╚" + "═" * 75 + "╝")
    
    conn = sqlite3.connect('autocve.db')
    # Return each row as a tuple
    rows = conn.execute('''SELECT cve_id, vendor, cvss_score, attack_vector, relevance FROM vulnerabilities ORDER BY date_added DESC''').fetchall()
    conn.close()
    
    if not rows:
        print("\n📭 No CVEs found in database")
        return
    
    # Print table
    print(f"\n┌{'─' * 15}┬{'─' * 15}┬{'─' * 8}┬{'─' * 12}┬{'─' * 10}┐")
    print(f"│{'CVE ID':<15}│{'Vendor':<15}│{'CVSS':<8}│{'Vector':<12}│{'Auto':<10}│")
    print(f"├{'─' * 15}┼{'─' * 15}┼{'─' * 8}┼{'─' * 12}┼{'─' * 10}┤")
    
    # Table rows
    for cve, vendor, cvss, vector, auto in rows:
        auto_icon = "🚗 Yes" if auto.lower() == "yes" else "❌ No"
        cvss_display = f"{cvss:.1f}" if cvss else "N/A" # float
        vendor_short = vendor[:14] if vendor != "Unknown" else "Unknown"
        vector_short = vector[:11] if vector != "Unknown" else "Unknown"
        
        print(f"│{cve:<15}│{vendor_short:<15}│{cvss_display:<8}│{vector_short:<12}│{auto_icon:9}│")
    
    print(f"└{'─' * 15}┴{'─' * 15}┴{'─' * 8}┴{'─' * 12}┴{'─' * 10}┘")
    print(f"\n📊 Total CVEs in database: {len(rows)}")

def list_automotive_cves():
    """Display only automotive CVEs"""
    print("\n╔" + "═" * 65 + "╗")
    print("║" + " " * 20 + "🚗 Automotive CVEs Only" + " " * 22 + "║")
    print("╚" + "═" * 65 + "╝")
    
    conn = sqlite3.connect('autocve.db')
    rows = conn.execute('''SELECT cve_id, vendor, cvss_score, attack_vector FROM vulnerabilities 
                          WHERE relevance LIKE '%yes%' ORDER BY date_added DESC''').fetchall()
    conn.close()
    
    if not rows:
        print("\n📭 No automotive-relevant CVEs found")
        return
    
    # Print table
    print(f"\n┌{'─' * 15}┬{'─' * 15}┬{'─' * 8}┬{'─' * 12}┐")
    print(f"│{'CVE ID':<15}│{'Vendor':<15}│{'CVSS':<8}│{'Vector':<12}│")
    print(f"├{'─' * 15}┼{'─' * 15}┼{'─' * 8}┼{'─' * 12}┤")
    
    # Table rows
    for cve, vendor, cvss, vector in rows:
        cvss_display = f"{cvss:.1f}" if cvss else "N/A"
        vendor_short = vendor[:14] if vendor != "Unknown" else "Unknown"
        vector_short = vector[:11] if vector != "Unknown" else "Unknown"
        
        print(f"│{cve:<15}│{vendor_short:<15}│{cvss_display:<8}│{vector_short:<12}│")
    
    print(f"└{'─' * 15}┴{'─' * 15}┴{'─' * 8}┴{'─' * 12}┘")
    print(f"\n🚗 Total automotive CVEs: {len(rows)}")

def main():
    """Main application loop"""
    init_db()
    
    while True:
        # show main menu
        show_header()

        choice = input("\n🎯 Choose option (1-4): ").strip()
        
        if choice == '1':
            add_cve()
        elif choice == '2':
            list_all_cves()
        elif choice == '3':
            list_automotive_cves()
        elif choice == '4':
            print("\n👋 Thank you for using AutoCVE Analyzer!")
            break
        else:
            print("\n❌ Invalid option! Choose 1-4.")
            input("🔁 Press Enter to try again...")
        if choice in '123':
            input("\n⏸️ Press Enter to continue...")
    
    print("\n╔" + "═" * 40 + "╗")
    print("║" + " " * 12 + "Session ended" + " " * 15 + "║")
    print("╚" + "═" * 40 + "╝")

if __name__ == "__main__":
    main()