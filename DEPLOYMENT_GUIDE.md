# Deployment Guide - WebAuthn FIDO2 Test Application

This guide provides multiple deployment options for the WebAuthn FIDO2 test application, addressing the issues with Vercel serverless deployment.

## Problems Addressed

1. **405 Method Not Allowed errors** in Vercel deployment
2. **Session state persistence** in serverless environments  
3. **Dynamic RP ID configuration** for different domains
4. **Vercel serverless compatibility** issues

## Solution 1: Improved Vercel Deployment (Recommended)

### Changes Made

1. **Fixed Vercel Configuration**: Updated `vercel.json` to use the correct serverless functions approach with `functions` and `rewrites`
2. **Dynamic Host Detection**: The application now automatically detects the deployment domain and sets the RP ID accordingly
3. **Production Environment Detection**: Server automatically switches between localhost (development) and dynamic domain (production)
4. **State Token System**: Maintains WebAuthn security in serverless environments

### Deployment Steps

1. **Deploy to Vercel**:
   ```bash
   vercel --prod
   ```

2. **Verify RP ID**: The application will automatically use your Vercel domain (e.g., `my-app.vercel.app`) as the RP ID

3. **Test WebAuthn flows**: Both simple and advanced registration/authentication should work

### Environment Variables (Optional)

Set these in your Vercel dashboard if needed:
- `SECRET_KEY`: Custom secret key for sessions
- `DOMAIN`: Override automatic domain detection

## Solution 2: Docker Deployment (Alternative)

For cases where serverless deployment continues to have issues, use Docker for a traditional server deployment.

### Quick Start

1. **Build and run locally**:
   ```bash
   ./docker-run.sh
   ```

2. **Or manually**:
   ```bash
   docker build -t webauthn-fido2-test .
   docker run -p 8080:8080 -e DOMAIN=your-domain.com webauthn-fido2-test
   ```

3. **Deploy to cloud platforms**:
   - **Railway**: Connect your GitHub repo and deploy
   - **Google Cloud Run**: `gcloud run deploy`
   - **AWS ECS**: Use the Dockerfile
   - **Azure Container Instances**: Deploy the container

### Docker Environment Variables

- `DOMAIN`: Your deployment domain (e.g., `my-app.railway.app`)
- `PORT`: Server port (default: 8080)
- `DOCKER_CONTAINER=true`: Enables production mode

## Technical Details

### Dynamic RP ID System

The application now automatically detects the deployment environment and sets the appropriate Relying Party ID:

- **Development**: Uses `localhost`
- **Vercel**: Uses `your-app.vercel.app`
- **Docker**: Uses the `DOMAIN` environment variable or detected host
- **Other platforms**: Auto-detects from request headers

### State Management

The application includes a robust state token system that works in serverless environments:

- State is serialized and sent to the client during `begin` operations
- Client automatically includes state token in `complete` operations  
- Maintains WebAuthn security while being serverless-compatible

### Compatibility

- ✅ **Vercel**: Serverless functions with automatic domain detection
- ✅ **Railway**: Docker deployment with custom domains
- ✅ **Google Cloud Run**: Containerized deployment
- ✅ **AWS/Azure**: Container deployment options
- ✅ **Local Development**: Works with localhost

## Troubleshooting

### If Vercel deployment still fails:

1. **Check Vercel logs**: `vercel logs`
2. **Verify Python runtime**: Ensure Vercel detects the Python runtime correctly
3. **Try Docker deployment**: Use the Docker option as a fallback

### If RP ID issues persist:

1. **Check browser console**: Look for WebAuthn errors related to RP ID mismatch
2. **Verify domain**: Ensure the detected domain matches your deployment URL
3. **Set DOMAIN environment variable**: Override automatic detection if needed

### Common Issues:

- **CORS errors**: Ensure your domain is properly configured
- **Session issues**: The state token system should handle this automatically
- **Import errors**: Check that all dependencies are in `requirements.txt`

## Testing

After deployment, test these flows:

1. **Simple Registration**: Should work without RP ID errors
2. **Simple Authentication**: Should authenticate existing credentials
3. **Advanced Registration**: Should work with custom configurations
4. **Advanced Authentication**: Should work with various options

The application should now work correctly on any deployment platform with proper WebAuthn functionality!