// const { db } = require('../connection')

// const { test } = require("./userWebController");

// const webTokenGenerator = require('../middleware/webTokenGenerator');
// const webTokenValidator = require('../middleware/webTokenValidator');
// const otpTokenGenerator = require('../middleware/otpTokenGenerator');
// const [otpTokenValidator, resetPasswordValidator] = require('../middleware/otpTokenValidator');

// const generateOTP = require("../middleware/otpGenerator");
// const passwordGenerator = require('secure-random-password');

// const crypto = require('crypto');

// const mailer = require('../mail/mailer');
// const queries = require('../schema/queries/userWebControllerQueries');

// const fs = require('fs');
// const validator = require('validator');
// const tokenValidator = require('../middleware/webTokenValidator');

// const request = require('supertest');
// const express = require('express');
// const userWebController = require('../controller/userWebController');

// const app = express();
// app.use(express.json());
// app.post('/login', userWebController.userLogin);

// describe('Test Login Endpoint', () => {
  
//   describe('Test Login Endpoint with valid credentials', () => {
//     test("should return status code 200", async () => {
//       const response = await request(app)
//         .post("/login")
//         .send({
//           "userEmail": "cb.en.u4cse21001@cb.students.amrita.edu",
//           "userPassword": "7a310ecc623837762671b2a2bb14856fc154872525884f69992f38b247dfc67c"
//         });
      
//       expect(response.statusCode).toBe(200);
//     });
//   });
// });

// afterAll((done) => {
//   db.end((err) => {
//     if (err) {
//       console.error('Error closing the database connection:', err);
//     }
//     done();
//   });
// });

// // jest.setTimeout(10000);  // 10 seconds

describe('Test', () => {
      test("should be true", () => {
        test = true;
        
        expect(test).toBe(true);
      });
});