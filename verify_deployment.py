#!/usr/bin/env python3
"""
Pre-deployment verification script for WebAuthn FIDO2 Test Application
Run this script before deploying to Vercel to ensure everything is configured correctly.
"""

import sys
import os

def check_file_exists(filepath, description):
    """Check if a file exists and report status"""
    if os.path.exists(filepath):
        print(f"✅ {description}: {filepath}")
        return True
    else:
        print(f"❌ {description}: {filepath} NOT FOUND")
        return False

def check_directory_exists(dirpath, description):
    """Check if a directory exists and report status"""
    if os.path.isdir(dirpath):
        file_count = len(os.listdir(dirpath))
        print(f"✅ {description}: {dirpath} ({file_count} files)")
        return True
    else:
        print(f"❌ {description}: {dirpath} NOT FOUND")
        return False

def main():
    print("🔍 WebAuthn FIDO2 Test Application - Vercel Deployment Verification")
    print("=" * 70)
    
    all_checks_passed = True
    
    # Check required files
    print("\n📁 Checking Configuration Files:")
    required_files = [
        ("vercel.json", "Vercel configuration"),
        ("requirements.txt", "Python dependencies"),
        (".vercelignore", "Vercel ignore rules"),
        ("runtime.txt", "Python runtime version"),
        ("package.json", "Node.js package metadata"),
        ("VERCEL_DEPLOYMENT.md", "Deployment guide"),
    ]
    
    for filepath, description in required_files:
        if not check_file_exists(filepath, description):
            all_checks_passed = False
    
    # Check required directories
    print("\n📂 Checking Directory Structure:")
    required_dirs = [
        ("api", "Serverless function directory"),
        ("public", "Static files directory"),
        ("fido2", "FIDO2 library"),
        ("examples/server", "Original Flask application"),
    ]
    
    for dirpath, description in required_dirs:
        if not check_directory_exists(dirpath, description):
            all_checks_passed = False
    
    # Check API entry point
    print("\n🐍 Checking Python Import Structure:")
    try:
        # Add project paths
        sys.path.insert(0, '.')
        sys.path.insert(0, 'examples/server')
        
        # Test FIDO2 library
        import fido2
        print(f"✅ FIDO2 library import successful (version: {fido2.__version__})")
        
        # Test Flask app
        from server.server import app as original_app
        print(f"✅ Original Flask app import successful ({len(original_app.url_map._rules)} routes)")
        
        # Test API entry point
        from api.index import app as api_app
        print(f"✅ API entry point import successful ({len(api_app.url_map._rules)} routes)")
        
    except Exception as e:
        print(f"❌ Python import failed: {e}")
        all_checks_passed = False
    
    # Check static files
    print("\n🌐 Checking Static Files:")
    static_files = [
        "public/index.html",
        "public/script.js", 
        "public/styles.css",
        "public/webauthn-json.browser-ponyfill.js",
    ]
    
    for filepath in static_files:
        if not check_file_exists(filepath, "Static file"):
            all_checks_passed = False
    
    # Final result
    print("\n" + "=" * 70)
    if all_checks_passed:
        print("🚀 SUCCESS: All verification checks passed!")
        print("📦 Your application is ready for Vercel deployment.")
        print("\n🔗 Deploy with:")
        print("   1. Connect your GitHub repository to Vercel, or")
        print("   2. Run: vercel --prod")
        print("\n📖 See VERCEL_DEPLOYMENT.md for detailed instructions.")
        return 0
    else:
        print("❌ FAILED: Some verification checks failed.")
        print("🔧 Please fix the issues above before deploying.")
        return 1

if __name__ == "__main__":
    exit(main())