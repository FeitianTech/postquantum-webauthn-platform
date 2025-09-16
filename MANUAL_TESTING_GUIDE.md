# Manual Testing Guide for Vercel Deployment

## Issues Fixed

### ✅ Primary Issue: 405 Method Not Allowed Error
- **Root Cause**: Session state not persisting between serverless function invocations
- **Solution**: Implemented state token system for serverless compatibility

### ✅ Secondary Issues Fixed
1. **Duplicate static route definition** in `api/index.py` - removed duplicate
2. **Session state crashes** - added robust error handling
3. **Serverless compatibility** - implemented state token system

## What Changed

### Backend Changes (`examples/server/server/server.py`)
1. **All `begin` endpoints** now provide `_stateToken` in response
2. **All `complete` endpoints** accept `_stateToken` in request body  
3. **Fallback compatibility** - still works with sessions for local development
4. **Error handling** - clear 400 errors instead of 500 crashes

### Frontend Changes (`public/script.js`)
1. **State token capture** - all flows now capture `_stateToken` from begin responses
2. **State token inclusion** - all complete requests include the state token
3. **Backward compatibility** - still works without state tokens

## Testing the Deployment

### 1. Simple Registration Flow
1. Go to your Vercel URL
2. Enter an email in the "Simple" tab
3. Click "Register"
4. Follow the WebAuthn prompts
5. **Expected**: Registration should complete successfully

### 2. Simple Authentication Flow  
1. Use the same email from registration
2. Click "Authenticate" 
3. Follow the WebAuthn prompts
4. **Expected**: Authentication should complete successfully

### 3. Advanced Registration Flow
1. Go to the "Advanced" tab
2. Modify the JSON if desired
3. Click "Advanced Register"
4. Follow the WebAuthn prompts
5. **Expected**: Registration should complete successfully

### 4. Error Scenarios (should work gracefully)
- If you get session errors, you should see clear error messages
- No more "405 Method Not Allowed" errors
- No more HTML error pages in JSON responses

## Technical Details

### State Token System
- **Format**: Base64-encoded pickled Python dict
- **Inclusion**: Automatic via JavaScript
- **Fallback**: Sessions still work for local development
- **Security**: Tokens are temporary and single-use

### Compatibility
- **Local development**: Works with sessions (no change needed)
- **Vercel deployment**: Works with state tokens (automatic)
- **Other serverless**: Should work with any stateless environment

## Troubleshooting

### If you still see issues:
1. **Clear browser cache** - old JavaScript might be cached
2. **Check browser console** - look for JavaScript errors
3. **Check Network tab** - verify `_stateToken` is being sent
4. **Try different browsers** - rule out browser-specific issues

### Expected Behavior
- ✅ Registration flows complete successfully
- ✅ Authentication flows complete successfully  
- ✅ Clear error messages (no HTML in JSON responses)
- ✅ No 405 Method Not Allowed errors
- ✅ No 500 Internal Server errors from session issues

The deployment should now work correctly in the Vercel serverless environment!