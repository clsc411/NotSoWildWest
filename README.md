# Wild Wild West Forum - First Github Connection
**Name:** Clara Scalzer  
**Project:** Midterm Project - Wild West Forum  
**Course:** COS 498 - Server Side Web-Development 

## Description:
This forum is a basic node.js and express web app using handlebars for templates. Users can register, log in, and post comments shared to a public page visible to all users. The forum is containerized using Docker and Nginx.

## How to run
**1.** Clone the repo: ' bash
   git clone https://github.com/clsc411/NotSoWildWest.git
   cd NotSoWildWest '
**2.** Build and start the containers: ' sudo docker compose up -d --build '
**3.** Configure Nginx Proxy Manager:
   *   Open ' http://localhost:81 ' (or your server IP:81)
   *   Login with default credentials:
       *   Email: `admin@example.com`
       *   Password: `changeme`
   *   Update your admin details when prompted.
   *   Go to **Hosts** -> **Proxy Hosts** -> **Add Proxy Host**.
   *   **Details Tab**:
       *   **Domain Names**: Enter your domain (e.g., `example.com`).
       *   **Scheme**: `http`
       *   **Forward Hostname**: `wildwest-nginx`
       *   **Forward Port**: `80`
       *   **Block Common Exploits**: Enable this.
   *   **SSL Tab**:
       *   **SSL Certificate**: Select "Request a new SSL Certificate".
       *   **Force SSL**: Enable this.
       *   **HTTP/2 Support**: Enable this.
       *   **Email Address**: Enter your email for Let's Encrypt.
       *   Agree to the Terms of Service and click **Save**.
**4.** Open the app in your browser at your domain (e.g., `https://example.com`).
**5.** To stop the running app: ' sudo docker compose down '

## Configuration

### Email Service (Gmail)
To enable password reset emails, you need to configure a Gmail account.

1.  Create a `.env` file in the root directory (copy from `.env.example`):
    ```bash
    cp .env.example .env
    ```
2.  Edit `.env` and add your Gmail credentials:
    ```env
    EMAIL_SERVICE=gmail
    EMAIL_USER=your-email@gmail.com
    EMAIL_PASS=your-app-password
    ```
    *Note: For Gmail, you must use an **App Password**, not your regular password. Go to Google Account > Security > 2-Step Verification > App passwords to generate one.*

## Notes
**Passwords are hashed using SQLite, but still exercise caution.**
**Data is persisted in `forum.db`.**

**URL:** ' [https://your-domain.com] '
