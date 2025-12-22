# Deploying DarkOrca Security Scanner on Render

This guide walks you through deploying the DarkOrca Security Scanner web application on Render.

## Prerequisites

1. A Render account (free tier available)
2. Your code pushed to a Git repository (GitHub, GitLab, or Bitbucket)
3. (Optional) WPScan API token for vulnerability database access
4. (Optional) Email API key (Resend) for email notifications
5. (Optional) OpenAI/Gemini API key for AI analysis

## Quick Start

### Option 1: Using render.yaml (Recommended)

1. **Push your code to GitHub/GitLab/Bitbucket**
   ```bash
   git push origin main
   ```

2. **Create a new Web Service on Render**
   - Go to https://dashboard.render.com
   - Click "New +" → "Web Service"
   - Connect your repository
   - Render will automatically detect `render.yaml` and use it

3. **Set Environment Variables**
   - Go to your service's "Environment" tab
   - Add any optional environment variables you need (see below)

4. **Deploy**
   - Render will automatically deploy when you push to your main branch

### Option 2: Manual Configuration

1. **Create a new Web Service**
   - Go to https://dashboard.render.com
   - Click "New +" → "Web Service"
   - Connect your repository

2. **Configure Settings**
   - **Name**: `darkorca-security-scanner` (or your preferred name)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 web_app:app`

3. **Set Environment Variables** (see below)

4. **Deploy**

## Required Dependencies

### 1. Add Gunicorn to requirements.txt

Gunicorn is needed for production WSGI server. Add it to `requirements.txt`:

```txt
gunicorn>=21.2.0
```

### 2. Update web_app.py for Production

The current `web_app.py` runs with `debug=True`. For production on Render, we need to ensure it can run with Gunicorn. The current setup should work, but you may want to modify the `if __name__ == '__main__'` block:

```python
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    # Only run debug mode if FLASK_ENV is not production
    debug_mode = os.getenv('FLASK_ENV', 'development').lower() != 'production'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
```

Note: With Gunicorn, the `if __name__ == '__main__'` block won't execute, so the debug setting doesn't matter. Gunicorn handles the server.

## Required Environment Variables

### Critical (Auto-set by Render)
- `PORT` - Automatically set by Render (you don't need to set this)

### Required for Production
- `SECRET_KEY` - Flask session encryption key (use Render's "Generate" option or create one)
- `FLASK_ENV` - Set to `production`
- `SESSION_COOKIE_SECURE` - Set to `true` (for HTTPS cookies)

### Recommended
- `SESSION_TIMEOUT_HOURS` - Session timeout (default: 24)
- `MAX_CONCURRENT_SCANS` - Max concurrent scans (default: 5, reduce for Render free tier)

### Optional
- `RESEND_API_KEY` - For email notifications
- `FROM_EMAIL` - Sender email address
- `OPENAI_API_KEY` - For AI analysis
- `GEMINI_API_KEY` - Alternative AI provider
- `WPSCAN_API_TOKEN` - WPScan vulnerability database access
- `CORS_ORIGINS` - Comma-separated list of allowed origins (default: `*`)

## Database Considerations

⚠️ **Important**: The application currently uses SQLite (`darkorca.db`), which is **ephemeral** on Render's free tier.

### Options:

1. **Use Render PostgreSQL** (Recommended for production)
   - Create a PostgreSQL database on Render
   - Modify `src/utils/database.py` to use PostgreSQL instead of SQLite
   - Update connection string to use `DATABASE_URL` environment variable

2. **Accept Ephemeral Storage** (For testing only)
   - Data will be lost on each deploy/restart
   - Users and saved scans won't persist
   - Only suitable for testing/demos

3. **Use External Database**
   - Use a managed database service (e.g., Supabase, Neon, Railway)
   - Update connection string accordingly

## External Scanner Dependencies

⚠️ **Challenge**: The application relies on external tools that may not be available on Render:

- **WPScan** (Ruby-based)
- **Nuclei** (Go-based)
- **Nmap** (C/C++)
- **SQLMap** (Python, but may need system dependencies)

### Solutions:

1. **Use Docker** (Recommended)
   - Create a Dockerfile with all dependencies
   - Render supports Docker deployments
   - See `Dockerfile.example` (to be created)

2. **Disable External Scanners**
   - Modify the orchestrator to skip scanners that aren't available
   - The app already handles missing scanners gracefully

3. **Use Render's Build Scripts**
   - Add build commands to install scanners
   - May be complex for Ruby/Go/C tools

## Render-Specific Configuration

### Using render.yaml

The `render.yaml` file is already configured with:
- Python 3.11.0
- Gunicorn as the WSGI server
- 2 workers, 4 threads
- 120-second timeout (for long-running scans)
- Starter plan (can be upgraded)

### Scaling

For the free tier:
- Set `MAX_CONCURRENT_SCANS` to `3` or lower
- Consider upgrading to a paid plan for better performance

For paid plans:
- Increase `MAX_CONCURRENT_SCANS` as needed
- Increase Gunicorn workers if needed

## Security Considerations

1. **HTTPS**: Render provides HTTPS automatically
2. **SECRET_KEY**: Must be set (generate a strong random key)
3. **SESSION_COOKIE_SECURE**: Set to `true` for HTTPS-only cookies
4. **CORS_ORIGINS**: Restrict to your domain(s) in production
5. **Database**: Use PostgreSQL for production, not SQLite

## Step-by-Step Deployment

1. **Add Gunicorn to requirements.txt**
   ```bash
   echo "gunicorn>=21.2.0" >> requirements.txt
   ```

2. **Commit render.yaml and Procfile**
   ```bash
   git add render.yaml Procfile requirements.txt
   git commit -m "Add Render deployment configuration"
   git push
   ```

3. **Create Web Service on Render**
   - Go to https://dashboard.render.com
   - Click "New +" → "Web Service"
   - Connect your repository
   - Render will auto-detect `render.yaml`

4. **Set Environment Variables**
   - Go to Environment tab
   - Add `SECRET_KEY` (click "Generate" for a secure key)
   - Add `FLASK_ENV` = `production`
   - Add `SESSION_COOKIE_SECURE` = `true`
   - Add any optional variables you need

5. **Deploy**
   - Click "Create Web Service"
   - Render will build and deploy automatically
   - Watch the logs for any issues

6. **Verify**
   - Visit your Render URL (e.g., `https://darkorca-security-scanner.onrender.com`)
   - Check `/health` endpoint
   - Test a scan

## Troubleshooting

### Build Fails
- Check that all dependencies are in `requirements.txt`
- Verify Python version compatibility

### App Crashes on Start
- Check logs in Render dashboard
- Verify `SECRET_KEY` is set
- Check that `PORT` environment variable is available

### Scanners Not Working
- Check if external tools are installed
- Review logs for "scanner not available" warnings
- Consider using Docker for full scanner support

### Database Issues
- SQLite files are ephemeral on Render
- Consider migrating to PostgreSQL

### Timeout Errors
- Increase Gunicorn timeout: `--timeout 180`
- Reduce `MAX_CONCURRENT_SCANS`
- Consider upgrading Render plan

## Alternative: Docker Deployment

For full scanner support, consider creating a Dockerfile:

```dockerfile
FROM python:3.11-slim

# Install system dependencies for scanners
RUN apt-get update && apt-get install -y \
    nmap \
    ruby \
    ruby-dev \
    build-essential \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Install Ruby gems (WPScan)
RUN gem install wpscan

# Install Go tools (Nuclei)
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 5000

# Run with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "web_app:app"]
```

Then use Docker deployment on Render instead of Python environment.

## Post-Deployment

1. **Test all endpoints** using the API test suite
2. **Monitor logs** for errors
3. **Set up monitoring** (Render provides basic monitoring)
4. **Configure backups** if using PostgreSQL
5. **Update CORS_ORIGINS** to your production domain

## Cost Estimate

- **Free Tier**: Limited (sleeps after 15 min inactivity, slower cold starts)
- **Starter Plan**: $7/month (always-on, better performance)
- **Professional Plan**: $25/month (more resources, better for production)

For production use, the Starter plan is recommended.

## Support

- Render Docs: https://render.com/docs
- Render Community: https://community.render.com
- Issues: Check application logs in Render dashboard
