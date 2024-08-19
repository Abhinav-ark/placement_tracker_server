const express = require('express')
const router = express.Router();

const authController = require('../controller/authController');
const managerWebController = require('../controller/managerWebController');
const userWebController = require('../controller/userWebController');

/* Test / Health Check */
router.get('/test', userWebController.test);


/* Auth Controller */

/* Post Endpoints */
router.post('/login', authController.userLogin);
router.post('/loginVerify', authController.loginVerify);
router.post('/studentLoginVerify', authController.studentVerify);
router.post('/studentRegister', authController.studentRegister);
router.post('/registerOfficial', authController.registerOfficial);
router.post('/addStudent', authController.addStudent);
router.post('/forgotPassword', authController.forgotPassword);
router.post('/resetPasswordVerify', authController.resetPasswordVerify);
router.post('/resetPassword', authController.resetPassword);


/* User Controller */

/* Get Endpoints */
router.get('/getCompanies', userWebController.getCompanies);

/* Post Endpoints */
router.post('/studentEditData', userWebController.studentEditData);
router.post('/getStudentPlacements', userWebController.getStudentPlacements);
router.post('/addCompany', userWebController.addCompany);
router.post('/addPlacementData', userWebController.addPlacementData);
router.post('/editPlacementDataById', userWebController.editPlacementDataById);


/* Manager Controller */

/* Get Endpoints */
router.get('/getRegisteredOfficials', managerWebController.getRegisteredOfficials);
router.get('/getCompanyHireData',managerWebController.getCompanyHireData);
router.get('/getTopFivePlacements',managerWebController.getTop5Placements);

/* Post Endpoints */
router.post('/toggleOfficialStatus', managerWebController.toggleOfficialAccountStatus);
router.post('/getCompanyHireDataByBatch',managerWebController.getCompanyHireDatabyBatch);
router.post('/getCompanyHireDataById',managerWebController.getCompanyHireDataById);
router.post('/getAllStudentData',managerWebController.getAllStudentData);
router.post('/getAllPlacedStudentData',managerWebController.getAllPlacedStudentsData);

module.exports = router;