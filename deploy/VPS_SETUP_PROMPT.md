# VPS Setup Prompt for Claude Code

Run Claude Code on your DigitalOcean VPS (via SSH) and paste the prompt below. It will walk you through the full setup interactively.

**Prerequisites:** A fresh Ubuntu 22.04+ droplet with SSH access and your API keys ready.

---

````text
Set up Steward on this VPS. Follow these steps in order, asking me for input where indicated:

1. **Check prerequisites.** Verify this is a Linux system. Check if Docker and Docker Compose (v2 plugin) are installed. Check if git is installed.

2. **Install missing prerequisites.** If Docker is not installed, install it using the official Docker apt repository for Ubuntu/Debian:
   - Add Docker's GPG key and apt repository
   - Install docker-ce, docker-ce-cli, containerd.io, docker-compose-plugin
   - Enable and start the Docker service
   If git is not installed, install it via apt.

3. **Create service user.** Create a system user `steward` with home directory `/opt/steward` if it doesn't already exist:
   ```
   useradd --system --create-home --home-dir /opt/steward --shell /usr/sbin/nologin steward
   usermod -aG docker steward
   ```

4. **Clone repository.** Clone the Steward repo into `/opt/steward/steward`:
   ```
   git clone https://github.com/<OWNER>/steward.git /opt/steward/steward
   ```
   Ask me for the repo URL if it's not a public repo.

5. **Configure environment.** Copy the env template and fill it in:
   ```
   cp /opt/steward/steward/.env.example /opt/steward/steward/.env
   ```
   Then ask me for each of these values interactively:
   - ANTHROPIC_API_KEY (required)
   - TELEGRAM_BOT_TOKEN (ask if I want Telegram — skip if no)
   - TELEGRAM_ALLOWED_USER_IDS (if Telegram enabled)

   For POSTGRES_PASSWORD, generate a secure random password:
   ```
   openssl rand -base64 32
   ```

   Write all values into the .env file.

6. **Lock down .env permissions:**
   ```
   chmod 600 /opt/steward/steward/.env
   chown steward:steward /opt/steward/steward/.env
   ```

7. **Configure firewall.** Set up UFW:
   ```
   ufw allow 22/tcp comment "SSH"
   ufw allow 8080/tcp comment "Steward HTTP"
   ufw --force enable
   ```
   Show me the firewall status after.

8. **Build and start.** From `/opt/steward/steward/deploy`:
   ```
   docker compose up -d --build
   ```

9. **Verify deployment:**
   - Run `docker compose ps` to show container status
   - Wait for health checks to pass, then run `curl -sf http://localhost:8080/health`
   - Show the last 20 lines of logs: `docker compose logs --tail=20`

10. **Print summary.** Show me a summary of useful commands:
    ```
    # View logs
    cd /opt/steward/steward/deploy && docker compose logs -f

    # Restart
    cd /opt/steward/steward/deploy && docker compose restart

    # Update to latest
    cd /opt/steward/steward && git pull && cd deploy && docker compose up -d --build

    # Stop
    cd /opt/steward/steward/deploy && docker compose down

    # Check status
    cd /opt/steward/steward/deploy && docker compose ps
    ```

If any step fails, diagnose the issue and fix it before continuing. Ask me for help if you get stuck on something that requires my input (like credentials or repo access).
````
