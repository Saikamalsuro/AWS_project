MedTrack - Healthcare Management System
MedTrack is a cloud-enabled healthcare platform designed to streamline patient-doctor interactions. Built with Flask, AWS DynamoDB, and SNS, it empowers patients to book appointments, manage profiles, and view their history, while doctors efficiently handle schedules and patient care.
🌟 Key Features

Role-Based Access: Secure registration and login for Patients, Doctors, and Admins.
Appointment Management:
Patients can book appointments with available doctors.
Doctors manage appointments via a dedicated dashboard.


Search Functionality: Find appointments by name or date.
Email Notifications: Automated confirmations and updates using SMTP.
Scalable Database: AWS DynamoDB for robust user and appointment data storage.
Responsive UI: Built with Bootstrap 5 for a seamless experience across devices.
Custom Error Handling: User-friendly 404 pages for better UX.
Optional AWS SNS: Enhanced notification system for scalability.
Dark Mode & Accessibility: Inclusive design for diverse users.
Deployment Ready: Optimized for AWS EC2.

🛠️ Tech Stack



Technology
Purpose



Flask (Python)
Backend framework


AWS DynamoDB
NoSQL database


AWS SNS
Notification system (optional)


Bootstrap 5
Responsive frontend


Jinja2
HTML templating


Werkzeug
Password hashing


SMTP (Gmail)
Email notifications


python-dotenv
Environment configuration


📂 Project Structure
MedTrack/
├── app.py                    # Main Flask application
├── requirements.txt          # Project dependencies
├── .env                     # Environment variables
├── templates/                # HTML templates
│   ├── base.html            # Base template
│   ├── index.html           # Home page
│   ├── register.html        # User registration
│   ├── login.html           # User login
│   ├── dashboard_patient.html # Patient dashboard
│   ├── dashboard_doctor.html  # Doctor dashboard
│   ├── book_appointment.html  # Appointment booking
│   ├── view_appointment_patient.html # Patient appointment view
│   ├── view_appointment_doctor.html  # Doctor appointment view
│   ├── search_results.html   # Appointment search results
│   ├── profile.html          # User profile
│   └── 404.html             # Custom error page
├── static/                   # Static assets
│   ├── css/
│   │   └── styles.css       # Custom styles
│   └── js/
│       └── scripts.js       # Client-side scripts
└── README.md                # Project documentation

🔧 Environment Setup
Create a .env file with the following:
SECRET_KEY=your_secret_key_here
EMAIL_USER=your_email_address
EMAIL_PASS=your_email_password_or_app_password
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=your_aws_region
DYNAMODB_USERS_TABLE=Users
DYNAMODB_APPOINTMENTS_TABLE=Appointments
SNS_TOPIC_ARN=your_topic_arn  # Optional

🗄️ DynamoDB Schema
MedTrack_Users



Attribute
Type



email
HASH (String)


name
String


role
String (patient/doctor/admin)


MedTrack_Appointments



Attribute
Type



appointment_id
HASH (String)


patient
String


doctor
String


date
String (YYYY-MM-DD)


time
String (HH:MM)


status
String (pending/confirmed/completed)


📧 Notifications

Email Alerts: Powered by Gmail SMTP for appointment confirmations, cancellations, and admin updates.
AWS SNS (Optional): Scalable notification system for high-volume use cases.

✅ Testing Coverage

Home page navigation
User registration (Doctor/Patient)
Secure login
Patient & Doctor dashboards
Appointment booking & search
DynamoDB CRUD operations
Email notifications
Custom error pages

🚀 Deployment
Deploy MedTrack on AWS EC2 with Gunicorn and Nginx for production, or use platforms like Heroku for simplicity. Ensure environment variables are securely configured.
🌐 Live Demo
(Add your hosted URL here if applicable)
👨‍💻 Author
Sai Kamal📧 Email: saikamalsuro@gmail.com🌐 GitHub: @saikamal
