import re
from openai import OpenAI
from dotenv import load_dotenv
import os

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def analyze_cve_with_gpt(cve_id, description):
    # Automotive keywords
    automotive_keywords = [ 'porsche', 'tesla', 'bmw', 'mercedes', 'toyota', 'automotive', 'vehicle', 'car', 'ecu', 'can bus', 'obd',
    'telematics', 'infotainment', 'adas', 'v2x', 'v2v', 'v2i', 'v2p', 'v2n', 'v2g', 'charging station', 'ev charger',
    'battery management', 'bosch', 'continental', 'denso', 'aptiv', 'valeo', 'magna', 'zf', 'vehicle tracking', 'carplay', 'android auto']
    
    # Check for automotive keywords
    text = (cve_id + " " + description).lower()
    found_keywords = [kw for kw in automotive_keywords if re.search(rf'\\b{kw}\\b', text)]
    has_automotive = len(found_keywords) > 0
    
    if found_keywords:
        print(f"🎯 Found keywords: {found_keywords}")
    
    # Analyze with GPT
    try:
        response = client.chat.completions.create(
            model="gpt-4", 
            messages=[{ "role": "user",
            "content": f"""Analyze CVE {cve_id}: {description}
            is this cve can be related to automotives?
            Automotive = YES if involves:
            - Car manufacturers (Porsche, Tesla, BMW, Toyota, etc.)
            - Auto suppliers (Bosch, Continental, Denso, etc.)
            - Vehicle systems (ECU, CAN bus, infotainment, OBD)
            - Charging stations, diagnostic tools

            Severity based on exploitability + impact.
            pay attention to the format!!!
            Your answer format:
            Severity: Critical / High / Medium /Low / not enough information
            Automotive: Yes / No"""}], temperature=0.1)
        reply = response.choices[0].message.content
        
        # Parse GPT response
        severity = extract_field(reply, 'severity', 'Unknown')
        relevance = extract_field(reply, 'automotive', 'Unknown')
        
        print(f"🤖 GPT said: {relevance}")
        print("📝 Reminder: GPT output may be inaccurate or overconfident. Always validate results if possible.")

        # Override if keywords found but GPT said no
        if has_automotive and relevance.lower() != 'yes':
            print(f"🔧 Override: Keywords found, setting to Yes")
            relevance = "Yes"
        
        return severity, relevance
        
    except Exception as e:
        print(f"❌ GPT Error: {e}")
        return "Unknown", "Yes" if has_automotive else "Unknown"

def extract_field(text, field_name, default):
    """Extract field from GPT response"""
    # Create pattern to match "field_name: value" and capture the value part
    pattern = rf'{field_name}:\s*(.+)'
    # Search case-insensitively and return captured group or default if not found
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else default