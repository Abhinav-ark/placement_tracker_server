const { db } = require('../connection')

const webTokenGenerator = require('../middleware/webTokenGenerator');
const webTokenValidator = require('../middleware/webTokenValidator');
const otpTokenGenerator = require('../middleware/otpTokenGenerator');
const [otpTokenValidator, resetPasswordValidator] = require('../middleware/otpTokenValidator');

const generateOTP = require("../middleware/otpGenerator");
const passwordGenerator = require('secure-random-password');

const crypto = require('crypto');

const mailer = require('../mail/mailer');
const queries = require('../schema/queries/userWebControllerQueries');

const fs = require('fs');
const validator = require('validator');
const tokenValidator = require('../middleware/webTokenValidator');
const requestValidator = require('../middleware/requestValidator');

module.exports = 
{
    test: async (req, res) => {
        return res.status(200).send({ "message": 'Ok' });
    },

    studentEditData : [
        tokenValidator,
        async (req, res) => {
        /*
        JSON
        {
            "studentRollNo": "<roll_no>",
            "studentEmail": "<email_id>",
            "studentName": "<name>",
            "studentSection": "<section>",
            "studentGender": "<M/F/O>",
            "studentBatch": "<batch>",
            "studentDept": "<dept>",
            "isHigherStudies": "<0/1>",
            "isPlaced": "<0/1>",
            "CGPA": "<XX.XX>"
        }
        */
     
        if (req.body.studentEmail === null || req.body.studentEmail === undefined || req.body.studentEmail === "" || req.body.studentName === null || req.body.studentName === undefined || req.body.studentName === "" || req.body.studentSection === null || req.body.studentSection === undefined || req.body.studentSection === "" || req.body.studentGender === null || req.body.studentGender === undefined || req.body.studentGender === "" || req.body.studentBatch === null || req.body.studentBatch === undefined || req.body.studentBatch === "" || req.body.studentDept === null || req.body.studentDept === undefined || req.body.studentDept === "" || req.body.isHigherStudies === null || req.body.isHigherStudies === undefined || req.body.isHigherStudies === "" ||  req.body.CGPA === null || req.body.CGPA === undefined || req.body.CGPA === "") {
            return res.status(400).send({ "message": "Missing details." });
        }

        if (req.body.studentGender !== "M" && req.body.studentGender !== "F" && req.body.studentGender !== "O") {
            return res.status(400).send({ "message": "Missing details." });
        }

        if (req.body.isHigherStudies !== "0" && req.body.isHigherStudies !== "1") {
            return res.status(400).send({ "message": "Missing details." });
        }

        if (parseFloat(req.body.CGPA) < 0 || parseFloat(req.body.CGPA) > 10) {
            return res.status(400).send({ "message": "Missing details." });
        }

        if (req.body.studentEmail.split("@")[1] !== "cb.students.amrita.edu") {
            return res.status(400).send({ "message": "Missing details." });
        }

        if (req.authorization_tier !== "0" && req.authorization_tier !== "1" && req.authorization_tier !== "2")
        {
            return res.status(400).send({ "message": "Access Restricted!" });
        }

        let db_connection = await db.promise().getConnection();

        try {

            if (req.authorization_tier === "1" || req.authorization_tier === "0"){
                //return res.status(400).send({ "message": "Functionality Not Available Yet!" });
                await db_connection.query(`LOCK TABLES studentData WRITE`);
                    
                await db_connection.query(`UPDATE  studentData SET studentName = ?, studentSection = ?, studentGender = ?, studentBatch = ?, isHigherStudies = ?, CGPA = ? where studentEmail = ?`, [req.body.studentName, req.body.studentSection, req.body.studentGender, req.body.studentBatch, req.body.isHigherStudies, req.body.CGPA ,req.body.studentEmail]);
                    
                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({ "message": "Student Data Updated!" });
            
            }
            if (req.authorization_tier === "2"){
                if (req.body.userEmail !== req.body.studentEmail){
                    return res.status(400).send({ "message": "Access Restricted!" });
                }
                else{
                    await db_connection.query(`LOCK TABLES studentData WRITE`);
                    
                    await db_connection.query(`UPDATE  studentData SET studentName = ?, studentSection = ?, studentGender = ?, studentBatch = ?, isHigherStudies = ?, CGPA = ? where studentEmail = ?`, [req.body.studentName, req.body.studentSection, req.body.studentGender, req.body.studentBatch, req.body.isHigherStudies, req.body.CGPA ,req.body.userEmail]);
                    
                    await db_connection.query(`UNLOCK TABLES`);

                    return res.status(200).send({ "message": "Student Data Updated!" });
                }

            }

        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - studentEditData - ${err}\n`);
            return res.status(500).send({ "message": "Internal Server Error." });
        } finally {
            await db_connection.query(`UNLOCK TABLES`);
            db_connection.release();
        }
        },
    ],

    addCompany: [
        /*
        JSON
        {
            companyName: "<company_name>"
        }
        */
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
                (req.body.userRole !== "0" && req.body.userRole !== "1" && req.body.userRole !== "2") ||
                req.body.companyName === null || req.body.companyName === undefined || req.body.companyName === "") {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            let company = null;

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData READ, companyData WRITE`);
                if (req.body.userRole === "0" || req.body.userRole === "1") {
                    let [manager] = await db_connection.query(`SELECT accountStatus,id from managementData WHERE managerEmail = ?`, [req.body.userEmail]);
                    if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    try {
                        company = await db_connection.query(`INSERT INTO companyData (companyName, managerId) VALUES (?, ?)`, [req.body.companyName, manager[0]["id"]]);
                    } catch (err) {
                        return res.status(400).send({ "message": "Company Registered Already!" });
                    }

                }
                else if (req.body.userRole === "2") {
                    let [student] = await db_connection.query(`SELECT * from studentData WHERE studentEmail = ?`, [req.body.userEmail]);

                    if (student.length === 0 || student[0]["studentAccountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    try {
                        company = await db_connection.query(`INSERT INTO companyData (companyName, studentId) VALUES (?, ?)`, [req.body.companyName, student[0]["id"]]);
                    } catch (err) {
                        console.log(err);
                        return res.status(400).send({ "message": "Company Registered Already!" });
                    }
                }

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({ "message": "Company added!", "companyId": company[0]["insertId"], "companyName": req.body.companyName });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addCompany - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }

        }
    ],

    getCompanies: [
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) || (req.body.userRole !== "1" && req.body.userRole !== "2" && req.body.userRole !== "0")) {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData READ, companyData READ`);

                let companies = null;

                if (req.body.userRole === "1" || req.body.userRole === "0") {

                    let [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);

                    if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    companies = await db_connection.query(`SELECT companyName,id from companyData`);
                }
                else if (req.body.userRole === "2") {
                    let [student] = await db_connection.query(`SELECT studentAccountStatus from studentData WHERE studentEmail = ?`, [req.body.userEmail]);

                    if (student.length === 0 || student[0]["studentAccountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    companies = await db_connection.query(`SELECT companyName,id from companyData`);
                }
                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({
                    "message": "Companies fetched!",
                    "companies": companies[0]
                });
            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getCompanies - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        }
    ],

    addPlacementData: [
        /*
        JSON
        {
            "studentRollNo":"<studentRollNo>", //Optional for student, Compulsory if manager adds student
            "companyId":<companyId> INTEGER,
            "ctc":<ctc> FLOAT,
            "jobRole":"<jobRole>",
            "jobLocation":"<jobLocation>", //Optional
            "placementDate":"<placementDate>",
            "isIntern":"<0/1>",
            "isPPO":"<0/1>",
            "isOnCampus":"<0/1>",
            "isGirlsDrive":"<0/1>",
            "extraData":"<extraData>" //Optional
        }
        */
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || (req.body.userRole !== "1" && req.body.userRole !== "0" && req.body.userRole !== "2") ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
                req.body.companyId === null || req.body.companyId === undefined || req.body.companyId === "" || isNaN(req.body.companyId) ||
                req.body.ctc === null || req.body.ctc === undefined || req.body.ctc === "" || isNaN(req.body.ctc) ||
                req.body.jobRole === null || req.body.jobRole === undefined || req.body.jobRole === "" ||
                req.body.placementDate === null || req.body.placementDate === undefined || req.body.placementDate === "" ||
                req.body.isIntern === null || req.body.isIntern === undefined || req.body.isIntern === "" || (req.body.isIntern !== "0" && req.body.isIntern !== "1") ||
                req.body.isPPO === null || req.body.isPPO === undefined || req.body.isPPO === "" || (req.body.isPPO !== "0" && req.body.isPPO !== "1") ||
                req.body.isOnCampus === null || req.body.isOnCampus === undefined || req.body.isOnCampus === "" || (req.body.isOnCampus !== "0" && req.body.isOnCampus !== "1") ||
                req.body.isGirlsDrive === null || req.body.isGirlsDrive === undefined || req.body.isGirlsDrive === "" || (req.body.isGirlsDrive !== "0" && req.body.isGirlsDrive !== "1")
            ) {
                return res.status(400).send({ "message": "Access Restricted!" });
            }


            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData READ, placementData WRITE`);

                if (req.body.userRole === "0" || req.body.userRole === "1") {

                    let [manager] = await db_connection.query(`SELECT accountStatus,id from managementData WHERE managerEmail = ?`, [req.body.userEmail]);
                    if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    if (req.body.studentRollNo === null || req.body.studentRollNo === undefined || req.body.studentRollNo === "") {
                        return res.status(400).send({ "message": "Missing Details!" });
                    }

                    [studentId] = await db_connection.query(`SELECT id from studentData WHERE studentRollNo = ?`, [req.body.studentRollNo]);
                    if (studentId.length === 0) {
                        return res.status(400).send({ "message": "Student Not registered!" });
                    }
                    studentId = studentId[0]["id"];

                    try {
                        if ((req.jobLocation === null || req.body.jobLocation === undefined || req.body.jobLocation === "") &&
                            (req.body.extraData === null || req.body.extraData === undefined || req.body.extraData === "")) {
                            await db_connection.query(`INSERT INTO placementData (companyId, ctc, jobRole, placementDate, isIntern, isPPO, isOnCampus, isGirlsDrive, studentId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, studentId]);
                        }
                        else if ((req.jobLocation !== null || req.body.jobLocation !== undefined || req.body.jobLocation !== "") &&
                            (req.body.extraData === null || req.body.extraData === undefined || req.body.extraData === "")) {
                            await db_connection.query(`INSERT INTO placementData (companyId, ctc, jobRole, jobLocation, placementDate, isIntern, isPPO, isOnCampus, isGirlsDrive, studentId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.jobLocation, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, studentId]);
                        }
                        else if ((req.jobLocation === null || req.body.jobLocation === undefined || req.body.jobLocation === "") &&
                            (req.body.extraData !== null || req.body.extraData !== undefined || req.body.extraData !== "")) {
                            await db_connection.query(`INSERT INTO placementData (companyId, ctc, jobRole, extraData, placementDate, isIntern, isPPO, isOnCampus, isGirlsDrive, studentId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.extraData, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, studentId]);
                        }
                        else {
                            await db_connection.query(`INSERT INTO placementData (companyId, ctc, jobRole, jobLocation, extraData, placementDate, isIntern, isPPo, isOnCampus, isGirlsDrive, studentId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.jobLocation, req.body.extraData, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, studentId]);
                        }

                    } catch (err) {
                        return res.status(400).send({ "message": "Placement Registered Already!" });
                    }

                }
                else if (req.body.userRole === "2") {
                    let [student] = await db_connection.query(`SELECT * from studentData WHERE studentEmail = ?`, [req.body.userEmail]);

                    if (student.length === 0 || student[0]["studentAccountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    let [studentId] = await db_connection.query(`SELECT id from studentData WHERE studentEmail = ?`, [req.body.userEmail]);
                    studentId = studentId[0]["id"];
                    try {
                        if ((req.jobLocation === null || req.body.jobLocation === undefined || req.body.jobLocation === "") &&
                            (req.body.extraData === null || req.body.extraData === undefined || req.body.extraData === "")) {
                            await db_connection.query(`INSERT INTO placementData (companyId, ctc, jobRole, placementDate, isIntern, isPPO, isOnCampus, isGirlsDrive, studentId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, studentId]);
                        }
                        else if ((req.jobLocation !== null || req.body.jobLocation !== undefined || req.body.jobLocation !== "") &&
                            (req.body.extraData === null || req.body.extraData === undefined || req.body.extraData === "")) {
                            await db_connection.query(`INSERT INTO placementData (companyId, ctc, jobRole, jobLocation, placementDate, isIntern, isPPO, isOnCampus, isGirlsDrive, studentId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.jobLocation, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, studentId]);
                        }
                        else if ((req.jobLocation === null || req.body.jobLocation === undefined || req.body.jobLocation === "") &&
                            (req.body.extraData !== null || req.body.extraData !== undefined || req.body.extraData !== "")) {
                            await db_connection.query(`INSERT INTO placementData (companyId, ctc, jobRole, extraData, placementDate, isIntern, isPPO, isOnCampus, isGirlsDrive, studentId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.extraData, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, studentId]);
                        }
                        else {
                            await db_connection.query(`INSERT INTO placementData (companyId, ctc, jobRole, jobLocation, extraData, placementDate, isIntern, isPPo, isOnCampus, isGirlsDrive, studentId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.jobLocation, req.body.extraData, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, studentId]);
                        }

                    } catch (err) {
                        return res.status(400).send({ "message": "Placement Registered Already!" });
                    }
                }

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({ "message": "Placement Data added!" });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addPlacementData - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        }
    ],


    editPlacementDataById: [
        /*
        JSON
        {
            "studentRollNo":"<studentRollNo>", //Optional for student, Compulsory if manager adds student
            "companyId":<companyId> INTEGER,
            "ctc":<ctc> FLOAT,
            "jobRole":"<jobRole>",
            "jobLocation":"<jobLocation>", //Optional
            "placementDate":"<placementDate>",
            "isIntern":"<0/1>",
            "isPPO":"<0/1>",
            "isOnCampus":"<0/1>",
            "isGirlsDrive":"<0/1>",
            "extraData":"<extraData>" //Optional
        }
        */
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || (req.body.userRole !== "1" && req.body.userRole !== "0" && req.body.userRole !== "2") ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
                req.body.companyId === null || req.body.companyId === undefined || req.body.companyId === "" || isNaN(req.body.companyId) ||
                req.body.ctc === null || req.body.ctc === undefined || req.body.ctc === "" || isNaN(req.body.ctc) ||
                req.body.jobRole === null || req.body.jobRole === undefined || req.body.jobRole === "" ||
                req.body.placementDate === null || req.body.placementDate === undefined || req.body.placementDate === "" ||
                req.body.isIntern === null || req.body.isIntern === undefined || req.body.isIntern === "" || (req.body.isIntern !== "0" && req.body.isIntern !== "1") ||
                req.body.isPPO === null || req.body.isPPO === undefined || req.body.isPPO === "" || (req.body.isPPO !== "0" && req.body.isPPO !== "1") ||
                req.body.isOnCampus === null || req.body.isOnCampus === undefined || req.body.isOnCampus === "" || (req.body.isOnCampus !== "0" && req.body.isOnCampus !== "1") ||
                req.body.isGirlsDrive === null || req.body.isGirlsDrive === undefined || req.body.isGirlsDrive === "" || (req.body.isGirlsDrive !== "0" && req.body.isGirlsDrive !== "1") ||
                req.body.placementID === null || req.body.placementID === undefined || req.body.placementID === "" || isNaN(req.body.placementID)
            ) {
                //console.log("test 1");
                return res.status(400).send({ "message": "Access Restricted!" });
            }


            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData READ, placementData WRITE`);

                if (req.body.userRole === "0" || req.body.userRole === "1") {

                    let [manager] = await db_connection.query(`SELECT accountStatus,id from managementData WHERE managerEmail = ?`, [req.body.userEmail]);
                    if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    if (req.body.studentRollNo === null || req.body.studentRollNo === undefined || req.body.studentRollNo === "") {
                        return res.status(400).send({ "message": "Missing Details!" });
                    }

                    // [studentId] = await db_connection.query(`SELECT id from studentData WHERE studentRollNo = ?`, [req.body.studentRollNo]);
                    // if (studentId.length === 0) {
                    //     return res.status(400).send({ "message": "Student Not registered!" });
                    // }
                    // studentId = studentId[0]["id"];

                    try {
                        if ((req.jobLocation === null || req.body.jobLocation === undefined || req.body.jobLocation === "") &&
                            (req.body.extraData === null || req.body.extraData === undefined || req.body.extraData === "")) {
                            await db_connection.query(`UPDATE placementData SET companyId=?, ctc=?, jobRole=?, placementDate=?, isIntern=?, isPPO=?, isOnCampus=?, isGirlsDrive=? where id=?`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, req.body.placementID]);
                        }
                        else if ((req.jobLocation !== null || req.body.jobLocation !== undefined || req.body.jobLocation !== "") &&
                            (req.body.extraData === null || req.body.extraData === undefined || req.body.extraData === "")) {
                            await db_connection.query(`UPDATE placementData SET companyId=?, ctc=?, jobRole=?, jobLocation=?, placementDate=?, isIntern=?, isPPO=?, isOnCampus=?, isGirlsDrive=? where id=?`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.jobLocation, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, req.body.placementID]);
                        }
                        else if ((req.jobLocation === null || req.body.jobLocation === undefined || req.body.jobLocation === "") &&
                            (req.body.extraData !== null || req.body.extraData !== undefined || req.body.extraData !== "")) {
                            await db_connection.query(`UPDATE placementData SET companyId=?, ctc=?, jobRole=?, extraData=?, placementDate=?, isIntern=?, isPPO=?, isOnCampus=?, isGirlsDrive=? where id=?`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.extraData, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, req.body.placementID]);
                        }
                        else {
                            await db_connection.query(`UPDATE placementData SET companyId=?, ctc=?, jobRole=?, jobLocation=?, extraData=?, placementDate=?, isIntern=?, isPPo=?, isOnCampus=?, isGirlsDrive=? where id=?`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.jobLocation, req.body.extraData, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, req.body.placementID]);
                        }

                    } catch (err) {
                        return res.status(400).send({ "message": "Placement Update Error!" });
                    }

                }
                else if (req.body.userRole === "2") {

                    [student] = await db_connection.query(`SELECT * from studentData WHERE studentEmail = ?`, [req.body.userEmail]);

                    if (student.length === 0 || student[0]["studentAccountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        //console.log("test 2");
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }           
                    
                    [studentId] = await db_connection.query('SELECT studentId from placementData WHERE id=?', [req.body.placementID]);
                    //console.log(studentId[0],student[0]["id"]);
                    if (studentId.length === 0 || studentId[0]["studentId"] !== student[0]["id"]) {
                        await db_connection.query(`UNLOCK TABLES`);
                        console.log("test 3");
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    try {
                        if ((req.jobLocation === null || req.body.jobLocation === undefined || req.body.jobLocation === "") &&
                            (req.body.extraData === null || req.body.extraData === undefined || req.body.extraData === "")) {
                            await db_connection.query(`UPDATE placementData SET companyId=?, ctc=?, jobRole=?, placementDate=?, isIntern=?, isPPO=?, isOnCampus=?, isGirlsDrive=? where id=?`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, req.body.placementID]);
                        }
                        else if ((req.jobLocation !== null || req.body.jobLocation !== undefined || req.body.jobLocation !== "") &&
                            (req.body.extraData === null || req.body.extraData === undefined || req.body.extraData === "")) {
                            await db_connection.query(`UPDATE placementData SET companyId=?, ctc=?, jobRole=?, jobLocation=?, placementDate=?, isIntern=?, isPPO=?, isOnCampus=?, isGirlsDrive=? where id=?`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.jobLocation, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, req.body.placementID]);
                        }
                        else if ((req.jobLocation === null || req.body.jobLocation === undefined || req.body.jobLocation === "") &&
                            (req.body.extraData !== null || req.body.extraData !== undefined || req.body.extraData !== "")) {
                            await db_connection.query(`UPDATE placementData SET companyId=?, ctc=?, jobRole=?, extraData=?, placementDate=?, isIntern=?, isPPO=?, isOnCampus=?, isGirlsDrive=? where id=?`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.extraData, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, req.body.placementID]);
                        }
                        else {
                            await db_connection.query(`UPDATE placementData SET companyId=?, ctc=?, jobRole=?, jobLocation=?, extraData=?, placementDate=?, isIntern=?, isPPo=?, isOnCampus=?, isGirlsDrive=? where id=?`, [req.body.companyId, req.body.ctc, req.body.jobRole, req.body.jobLocation, req.body.extraData, req.body.placementDate, req.body.isIntern, req.body.isPPO, req.body.isOnCampus, req.body.isGirlsDrive, req.body.placementID]);
                        }

                    } catch (err) {
                        return res.status(400).send({ "message": "Placement Update Error!" });
                    }
                }

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({ "message": "Placement Data Updated!" });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - editPlacementDataById - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        }
    ],


    getStudentPlacements: [
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
                (req.authorization_tier !== "0" && req.authorization_tier !== "1" && req.authorization_tier !== "2")) {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let studentId = req.body.studentId;

            if ((req.authorization_tier === "1" || req.authorization_tier === "0") && (studentId === null || studentId === undefined || studentId === "")) {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                if (req.authorization_tier === "0" || req.authorization_tier === "1") {

                    await db_connection.query(`LOCK TABLES managementData READ`);

                    let [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);
                    if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    await db_connection.query(`UNLOCK TABLES`);

                    await db_connection.query(`LOCK TABLES studentData READ`);

                    let [student] = await db_connection.query(`SELECT 
                    id AS studentId,
                    studentRollNo,
                    studentEmail,
                    studentName,
                    studentSection,
                    studentGender,
                    studentBatch,
                    studentDept,
                    isHigherStudies,
                    isPlaced,
                    CGPA,
                    studentAccountStatus from studentData WHERE id = ?`, [studentId]);

                    if (student.length === 0) {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(400).send({ "message": "Student Not Registered!" });
                    }

                    await db_connection.query(`UNLOCK TABLES`);

                    await db_connection.query(`LOCK TABLES placementData p READ, companyData c READ`);

                    let [studentPlacementData] = await db_connection.query(`select p.id as placementID, companyID, companyName, ctc, jobRole, jobLocation, placementDate, isIntern, isPPO, isOnCampus, isGirlsDrive, extraData from placementData p left join companyData c on p.companyId = c.id WHERE p.studentId = ? ORDER BY p.ctc;`, [studentId]);

                    if (studentPlacementData.length === 0) {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(200).send({ 
                            "placementData": [],
                            "student": student[0],
                            "message": "No Placement Data Found!" 
                        });
                    }

                    await db_connection.query(`UNLOCK TABLES`);

                    return res.status(200).send({
                        "message": "Placement Data Fetched!",
                        "student": student[0],
                        "placementData": studentPlacementData
                    });

                } else if (req.authorization_tier === "2") {
                    await db_connection.query(`LOCK TABLES studentData READ`);

                    let [student] = await db_connection.query(`SELECT * from studentData WHERE studentEmail = ?`, [req.body.userEmail]);

                    if (student.length === 0 || student[0]["studentAccountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                    await db_connection.query(`UNLOCK TABLES`);

                    await db_connection.query(`LOCK TABLES placementData p READ, companyData c READ`);

                    let [studentPlacementData] = await db_connection.query(`select p.id as placementID, companyID, companyName, ctc, jobRole, jobLocation, placementDate, isIntern, isPPO, isOnCampus, isGirlsDrive, extraData from placementData p left join companyData c on p.companyId = c.id WHERE p.studentId = ? ORDER BY p.ctc;`, [student[0]["id"]]);

                    if (studentPlacementData.length === 0) {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(200).send({ 
                            "placementData": [],
                            "message": "No Placement Data Found!" 
                        });
                    }

                    await db_connection.query(`UNLOCK TABLES`);

                    return res.status(200).send({
                        "message": "Placement Data Fetched!",
                        "placementData": studentPlacementData
                    });
                }

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getStudentPlacements - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        }
    ]

    // incomplete
    // getStats: [
    //     webTokenValidator,
    //     async (req, res) => {
    //         if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" ||
    //             req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
    //             (req.authorization_tier !== "0" && req.authorization_tier !== "1") ||
    //             req.body.batch === null || req.body.batch === undefined || req.body.batch === "") {
    //             return res.status(400).send({ "message": "Access Restricted!" });
    //         }

    //         let db_connection = await db.promise().getConnection();

    //         try {

    //             // Max Min Avg CTC
    //             await db_connection.query(`LOCK TABLES managementData READ`);
    //             let [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);

    //             if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
    //                 await db_connection.query(`UNLOCK TABLES`);
    //                 return res.status(401).send({ "message": "Access Restricted!" });
    //             }

    //             await db_connection.query(`LOCK TABLES placementData READ`);

    //             let [maxMinAvgCTC] = await db_connection.query(`SELECT MAX(ctc) as maxCTC, MIN(ctc) as minCTC, AVG(ctc) as avgCTC from placementData`);

    //             await db_connection.query(`UNLOCK TABLES`);

    //             // Total Placed Students

    //             await db_connection.query(`LOCK TABLES studentData READ`);

    //             let [placedCount] = await db_connection.query(`SELECT COUNT(id) as totalPlacedStudents from studentData WHERE isPlaced = 1 AND studentBatch = ?`, [req.body.batch]);
    //             let [totalStudents] = await db_connection.query(`SELECT COUNT(id) as totalStudents from studentData WHERE studentBatch = ?`, [req.body.batch]);

    //             await db_connection.query(`UNLOCK TABLES`);

    //             /*
    //             Single Offer
    //             Double Offers
    //             Triple Offer
    //             More than 3 offers 
    //             */

    //             await db_connection.query(`LOCK TABLES studentData READ, placementData READ`);

    //             let [singleOffer] = await db_connection.query(`SELECT COUNT(id) as singleOffer from studentData WHERE isPlaced = 1 AND studentBatch = ? AND id IN (SELECT studentId from placementData GROUP BY studentId HAVING COUNT(studentId) = 1)`, [req.body.batch]);

    //             let [doubleOffer] = await db_connection.query(`SELECT COUNT(id) as doubleOffer from studentData WHERE isPlaced = 1 AND studentBatch = ? AND id IN (SELECT studentId from placementData GROUP BY studentId HAVING COUNT(studentId) = 2)`, [req.body.batch]);

    //             let [tripleOffer] = await db_connection.query(`SELECT COUNT(id) as tripleOffer from studentData WHERE isPlaced = 1 AND studentBatch = ? AND id IN (SELECT studentId from placementData GROUP BY studentId HAVING COUNT(studentId) = 3)`, [req.body.batch]);

    //             let [moreThan3Offer] = await db_connection.query(`SELECT COUNT(id) as moreThan3Offer from studentData WHERE isPlaced = 1 AND studentBatch = ? AND id IN (SELECT studentId from placementData GROUP BY studentId HAVING COUNT(studentId) > 3)`, [req.body.batch]);

    //             await db_connection.query(`UNLOCK TABLES`);

    //             let [totalOffers] = singleOffer[0]["singleOffer"] + doubleOffer[0]["doubleOffer"] + tripleOffer[0]["tripleOffer"] + moreThan3Offer[0]["moreThan3Offer"];



    //         } catch (err) {
    //             console.log(err);
    //             const time = new Date();
    //             fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getAllStudentData - ${err}\n`);
    //             return res.status(500).send({ "message": "Internal Server Error." });
    //         } finally {
    //             await db_connection.query(`UNLOCK TABLES`);
    //             db_connection.release();
    //         }
    //     }
    // ]

}