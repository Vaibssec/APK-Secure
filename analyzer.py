import hashlib
from androguard.core.apk import APK


# Calculate SHA-256 hash of the APK
def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for block in iter(lambda: file.read(4096), b""):
            sha256.update(block)

    return sha256.hexdigest()


# Analyze APK information and permissions
def analyze_apk(file_path):
    apk = APK(file_path)

    package_name = apk.get_package()
    app_name = apk.get_app_name()
    version = apk.get_androidversion_name()
    permissions = apk.get_permissions()

    suspicious_keywords = [
        "READ_SMS",
        "SEND_SMS",
        "RECEIVE_SMS",
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "SYSTEM_ALERT_WINDOW",
        "REQUEST_INSTALL_PACKAGES",
        "RECEIVE_BOOT_COMPLETED",
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "RECORD_AUDIO",
        "CAMERA",
        "READ_PHONE_STATE",
        "INTERNET"
    ]

    suspicious_permissions = []

    for permission in permissions:
        permission_name = permission.split(".")[-1]

        for keyword in suspicious_keywords:
            if keyword in permission_name:
                suspicious_permissions.append(permission_name)
                break

    # Remove duplicate permissions
    suspicious_permissions = list(set(suspicious_permissions))

    # Risk scoring
    risk_score = 0

    for permission in suspicious_permissions:
        if permission in ["SEND_SMS", "READ_SMS", "RECEIVE_SMS"]:
            risk_score += 25

        elif permission in [
            "REQUEST_INSTALL_PACKAGES",
            "SYSTEM_ALERT_WINDOW",
            "RECORD_AUDIO"
        ]:
            risk_score += 20

        elif permission in [
            "READ_CONTACTS",
            "WRITE_CONTACTS",
            "READ_PHONE_STATE"
        ]:
            risk_score += 10

        else:
            risk_score += 5

    # Limit score to 100
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        verdict = "HIGH RISK"
    elif risk_score >= 40:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    return {
        "app_name": app_name,
        "package_name": package_name,
        "version": version,
        "permissions": permissions,
        "suspicious_permissions": suspicious_permissions,
        "risk_score": risk_score,
        "verdict": verdict,
        "sha256": calculate_hash(file_path)
    }