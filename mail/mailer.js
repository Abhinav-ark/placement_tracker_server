require('dotenv').config();
const mailer = require('nodemailer');
const fs = require('fs');
const TEMPLATE_OFFICIAL_CREATED = require('./template_acc_reg');
const TEMPLATE_STUDENT_CREATED = require('./template_student_acc_reg');
const TEMPLATE_OTP = require('./template_otp');
const TEMPLATE_ACCOUNT_DEACTIVATED = require('./template_account_deactivated');
const TEMPLATE_PWRESET_OTP = require('./template_pwreset_otp');

const transporter = mailer.createTransport({
    service: process.env.MAIL_SERVICE ?? 'Gmail',
    host: process.env.MAIL_HOST ?? 'smtp.gmail.com',
    port: process.env.MAIL_PORT ?? 587,
    tls: {
        ciphers: 'SSLv3',
        rejectUnauthorized: false,
    },
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASSWORD
    }
});

module.exports = {
    officialCreated: (fullName, userEmail, password) => {
        var mailOptions = {
            from: {
                name: "Amrita Placement Tracker",
                address: process.env.MAIL_USER
            },
            to: userEmail,
            subject: 'Welcome to Amrita Placement Tracker',
            html: TEMPLATE_OFFICIAL_CREATED(userEmail, fullName, password)
        }

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('officialCreated Email sent: ' + userEmail);
            }
        });
    },

    studentCreated: (fullName, userEmail, password) => {
        var mailOptions = {
            from: {
                name: "Amrita Placement Tracker",
                address: process.env.MAIL_USER
            },
            to: userEmail,
            subject: 'Welcome to Amrita Placement Tracker',
            html: TEMPLATE_STUDENT_CREATED(userEmail, fullName, password)
        }

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('studentCreated Email sent: ' + userEmail);
            }
        });
    },

    reset_PW_OTP: (userName, otp, userEmail) => {
        var mailOptions = {
            from: {
                name: "Amrita Placement Tracker",
                address: process.env.MAIL_USER
            },
            to: userEmail,
            subject: 'Reset Password OTP - Amrita Placement Tracker',
            html: TEMPLATE_PWRESET_OTP(otp, userName)
        }

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
                //console.log('error while sending otp');
            } else {
                console.log('PasswordResetOTP Email sent: ' + userEmail);
            }
        });
    },

    loginOTP: (userName, otp, userEmail) => {
        var mailOptions = {
            from: {
                name: "Amrita Placement Tracker",
                address: process.env.MAIL_USER
            },
            to: userEmail,
            subject: 'Account Registration OTP - Amrita Placement Tracker',
            html: TEMPLATE_OTP(otp, userName)
        }

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
                //console.log('error while sending otp');
            } else {
                console.log('loginOtp Email sent: ' + userEmail);
            }
        });
    },

    accountDeactivated: (fullName, userEmail) => {
        var mailOptions = {
            from: {
                name: "Amrita Placement Tracker",
                address: process.env.MAIL_USER
            },
            to: userEmail,
            subject: 'Account Deactivated - Amrita Placement Tracker',
            html: TEMPLATE_ACCOUNT_DEACTIVATED(userEmail, fullName)
        }

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('officialCreated Email sent: ' + userEmail);
            }
        });
    }
        
}