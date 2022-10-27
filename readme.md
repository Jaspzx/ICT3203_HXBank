# HX Bank

## To Access the web portal
[HX Bank](https://hxbank.tk)

## Installation
1. Clone the repository
2. Open terminal in the cloned repository and run the script below
```
pip3 install virtualenv
python -m venv venv-win
venv-win\Scripts\Activate
pip install -r requirements.txt
```
3. Run the program
```
python main.py
```

### Docker Commands
To build and start the docker container. Run:
```
docker compose up -d
```
To stop and remove all the containers and images. Run:
```
docker compose down --rmi local
```

### Project Structure
```
HXBank
|── jenkins/
|   |── Dockerfile
├── nginx/
│   ├── Dockerfile
│   │── nginx.conf
├── webportal/
│   ├── controllers/
│   │   ├── AccountManagementController.py
│   │   ├── BankAccountController.py
│   │   ├── EmailManagementController.py
│   │   ├── MessageManagementController.py
│   │   ├── TransferManagementController.py
│   ├── models/
│   │   ├── Account.py
│   │   ├── Message.py
│   │   ├── Transaction.py
│   │   ├── Transferee.py
│   │   ├── User.py
│   ├── static/
│   │   ├── css/
│   |   |   ├── style.css
│   │   ├── images/
│   |   |   ├── HXBank_logo.png
|   |   |   |── avatar.png
|   |   |   |── bank_image.png
|   |   |   |── card.svg
|   |   |   |── card_image.png
|   |   |   |── card_img.png
|   |   |   |── mobile_banking.png
│   │   ├── js/
│   │   │   ├── dashboard.js
│   │   ├── vendor/
│   │   │   ├── bootstrap/
│   │   │   │   ├── bootstrap.bundle.min.js
│   │   │   │   ├── bootstrap.bundle.min.js.map
│   │   │   │   ├── bootstrap.min.css
│   │   │   │   ├── bootstrap.min.css.map
│   │   │   ├── chartjs/
│   │   │   │   ├── chart.min.js
│   │   │   ├── datatable/
|   |   |   |   ├── datatables.css
|   |   |   |   ├── datatables.js
|   |   |   |   ├── datatables.min.css
|   |   |   |   ├── datatables.min.js
│   │   │   ├── jquery/
│   │   │   │   ├── jquery.min.js
│   │   │   ├── material-icons/
│   │   │   │   ├── MaterialIcons-Regular.ttf
│   │   │   │   ├── MaterialIconsOutlined-Regular.otf
│   │   │   │   ├── MaterialIconsRound-Regular.otf
│   │   │   │   ├── MaterialIconsSharp-Regular.otf
│   │   │   │   ├── MaterialIconsTwoTone-Regular.otf
│   │   │   ├── public-sans/
│   │   │   │   ├── public-sans-v14-latin-300.eot
│   │   │   │   ├── public-sans-v14-latin-300.svg
│   │   │   │   ├── public-sans-v14-latin-300.ttf
│   │   │   │   ├── public-sans-v14-latin-300.woff
│   │   │   │   ├── public-sans-v14-latin-300.woff2
|   ├── template
|   |   ├── admin/
|   |   |   ├── admin-dashboard.html
|   |   |   ├── enrol-admin.html
|   |   |   ├── enrolment-successful.html
|   |   |   ├── transaction-management.html
|   |   ├── email_templates/
|   |   |   ├── activate.html
|   |   |   ├── otp.html
|   |   |   ├── recipient.html
|   |   |   ├── reset.html
|   |   |   ├── top-up.html
|   |   |   ├── transfer-limit.html
|   |   |   ├── transfer-pending.html
|   |   |   ├── transfer-success.html
|   │   ├── includes/
|   |   |   ├── footer.html
|   |   |   ├── navigation.html
|   │   ├── layouts/
|   |   |   ├── 404.html
|   |   |   ├── 500.html
|   │   │   ├── base.html
|   |   |   ├── about.html
|   |   |   ├── account-setting.html
|   |   |   ├── add-transferee.html
|   |   |   ├── approval-required.html
|   |   |   ├── auth-change-otp.html
|   |   |   ├── change-otp.html
|   |   |   ├── change-pwd.html
|   |   |   ├── compose.html
|   |   |   ├── dashboard.html
|   |   |   ├── home.html
|   |   |   ├── login.html
|   |   |   ├── message-center.html
|   |   |   ├── otp-input.html
|   |   |   ├── otp-setup.html
|   |   |   ├── profile.html
|   |   |   ├── register.html
|   |   |   ├── reset-authenticate.html
|   |   |   ├── reset-identify.html
|   |   |   ├── reset-pwd.html
|   |   |   ├── reset-success.html
|   |   |   ├── robots.txt
|   |   |   ├── set-transferee-limit.html
|   |   |   ├── success.html
|   |   |   ├── top-up.html
|   |   |   ├── transaction-history.html
|   |   |   ├── transfer.html
|   |   |   ├── transfer-onetime.html
|   |   |   ├── transfer.html
|   |   |   ├── verify-email.html
|   |   |   ├── view-transferee.html
|   ├── utils/
|   │   ├── interact_db.py
|   │   ├── message.py
│   ├── .gitignore
|   |── _init_.py
|   ├── flask_simple_crypt.py
|   ├── forms.py
|   ├── views.py
├── .dockerignore
├── .gitignore
├── app.ini
├── docker-compose.yml
├── main.py
├── readme.md
├── requirements.txt
```