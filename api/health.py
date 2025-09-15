"""
Health check endpoint for Vercel deployment
"""

from api.index import app

@app.route('/api/health')
def health_check():
    """Simple health check endpoint"""
    return {
        "status": "healthy",
        "message": "WebAuthn FIDO2 Test Application is running",
        "routes": len(app.url_map._rules)
    }

if __name__ == "__main__":
    print("Health check module loaded")