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

module.exports = {

    getRegisteredOfficials: [
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) || req.body.userRole !== "1") {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ`);

                // check if actually admin
                let [admin] = await db_connection.query(`SELECT * from managementData WHERE managerEmail = ? AND managerRole = ?`, [req.body.userEmail, "1"]);

                if (admin.length === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Access Restricted!" });
                }

                // select all fields except password.

                let [managers] = await db_connection.query(`SELECT id, managerEmail, managerName, managerRole, createdAt, accountStatus from managementData WHERE id != ?`, [admin[0].id]);

                if (managers.length === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(200).send({ "message": "No managers registered!", "managers": [] });
                }

                await db_connection.query(`UNLOCK TABLES`);
                return res.status(200).send({ "message": "Managers fetched!", "managers": managers });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getRegisteredOfficials - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        },
    ],

    toggleOfficialAccountStatus: [
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }

        JSON
        {
            "managerId": "<manager_id>",
            "accountStatus": "<0/1/2>"
        }
        */
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) || req.body.userRole !== "1") {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            if (req.body.managerId === null || req.body.managerId === undefined || req.body.managerId === "" || req.body.accountStatus === null || req.body.accountStatus === undefined || req.body.accountStatus === "") {
                return res.status(400).send({ "message": "Missing details." });
            }

            if (req.body.accountStatus !== "0" && req.body.accountStatus !== "1" && req.body.accountStatus !== "2") {
                return res.status(400).send({ "message": "Invalid account status!" });
            }

            let db_connection = await db.promise().getConnection();

            try {

                await db_connection.query(`LOCK TABLES managementData WRITE`);

                // check if actually admin
                let [admin] = await db_connection.query(`SELECT * from managementData WHERE managerEmail = ? AND managerRole = ?`, [req.body.userEmail, "1"]);

                if (admin.length === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Access Restricted!" });
                }

                // check if manager exists.

                let [manager] = await db_connection.query(`SELECT * from managementData WHERE id = ?`, [req.body.managerId]);

                if (manager.length === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(400).send({ "message": "Manager doesn't exist!" });
                }

                // 2 -> 0, 0 -> 2, 1 -> 2
                // Only the manager themselves can change their account status from 0 to 1.
                if ((manager[0].accountStatus === "2" && req.body.accountStatus === "0") || (manager[0].accountStatus === "0" && req.body.accountStatus === "2") || (manager[0].accountStatus === "1" && req.body.accountStatus === "2")) {
                    await db_connection.query(`UPDATE managementData SET accountStatus = ? WHERE id = ?`, [req.body.accountStatus, req.body.managerId]);
                    await db_connection.query(`UNLOCK TABLES`);

                    if (req.body.accountStatus === "2") {
                        // send mail
                        mailer.accountDeactivated(manager[0].managerName, manager[0].managerEmail);
                    }

                    return res.status(200).send({ "message": "Account status updated!", "accountStatus": req.body.accountStatus });
                }

                await db_connection.query(`UNLOCK TABLES`);
                return res.status(400).send({ "message": "Action not permitted" });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - toggleOfficialAccountStatus - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            }

        }
    ],

    getCompanyHireData: [
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || (req.body.userRole !== "1" && req.body.userRole !== "0" && req.body.userRole !== "2") ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail)) {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData READ, placementData p READ, companyData c READ, studentData s READ`);

                if (req.body.userRole === "0" || req.body.userRole === "1") {

                    let [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);

                    if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }
                }
                else if (req.body.userRole === "2") {
                    let [student] = await db_connection.query(`SELECT * from studentData WHERE studentEmail = ?`, [req.body.userEmail]);

                    if (student.length === 0 || student[0]["studentAccountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                }

                // extract section wise hire count for each company

                // [companyHireData] = await db_connection.query(`select p.companyId, c.companyName, p.ctc, p.jobRole, 
                //     count(p.id) as totalHires from placementData p left join companyData c 
                //     on p.companyId = c.id group by p.companyId, p.ctc, p.jobRole order by p.companyId;`);

                [companyHireData] = await db_connection.query(`select p.companyId, c.companyName, p.ctc, p.jobRole, s.studentSection, COUNT(p.id) AS totalHires FROM placementData p join companyData c on p.companyId=c.id join studentData s on p.studentId=s.id group by p.companyId, p.ctc, p.jobRole, s.studentSection order by p.companyId, p.ctc, p.jobRole, s.studentSection;`);

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({
                    "message": "Company Wise Placement Data Fetched!",
                    "companyHireData": companyHireData
                });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getCompanyHireData - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }

        }
    ],

    getCompanyHireDatabyBatch: [
        /*
        JSON
        {
            "studentBatch": "<studentBatch>"
        }
        */
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || (req.body.userRole !== "1" && req.body.userRole !== "0" && req.body.userRole !== "2") ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
                (req.body.studentBatch === null || req.body.studentBatch === undefined || req.body.studentBatch === "" || isNaN(req.body.studentBatch))) {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData READ, placementData p READ, companyData c READ, studentData s READ`);

                if (req.body.userRole === "0" || req.body.userRole === "1") {

                    let [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);

                    if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }
                }
                else if (req.body.userRole === "2") {
                    let [student] = await db_connection.query(`SELECT * from studentData WHERE studentEmail = ?`, [req.body.userEmail]);

                    if (student.length === 0 || student[0]["studentAccountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                }

                // extract section wise hire count for each company

                // [companyHireData] = await db_connection.query(`select p.companyId, c.companyName, p.ctc, p.jobRole, 
                //     count(p.id) as totalHires from placementData p left join companyData c 
                //     on p.companyId = c.id group by p.companyId, p.ctc, p.jobRole order by p.companyId;`);

                [companyHireData] = await db_connection.query(`select p.companyId, c.companyName, p.ctc, p.jobRole, s.studentSection, COUNT(p.id) AS totalHires FROM placementData p join companyData c on p.companyId=c.id join studentData s on p.studentId=s.id WHERE s.studentBatch = ? group by p.companyId, p.ctc, p.jobRole, s.studentSection order by p.companyId, p.ctc, p.jobRole, s.studentSection;`, [req.body.studentBatch]);

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({
                    "message": "Company Wise Placement Data Fetched!",
                    "companyHireData": companyHireData
                });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getCompanyHireData - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }

        }
    ],

    getCompanyHireDataById: [
        /*
        JSON
        {
            "companyId":<companyId> INTEGER,
            "studentBatch": "<studentBatch>"
        }
        */
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || (req.body.userRole !== "1" && req.body.userRole !== "0" && req.body.userRole !== "2") ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
                req.body.companyId === null || req.body.companyId === undefined || req.body.companyId === "" || isNaN(req.body.companyId)) {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData s READ, placementData p READ, companyData c READ`);

                if (req.body.userRole === "0" || req.body.userRole === "1") {

                    let [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);

                    if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }
                }
                else if (req.body.userRole === "2") {
                    let [student] = await db_connection.query(`SELECT * from studentData s WHERE s.studentEmail = ?`, [req.body.userEmail]);

                    if (student.length === 0 || student[0]["studentAccountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                }

                [companyName] = await db_connection.query(`select c.companyName from companyData c where id = ?`, [req.body.companyId]);
                if (companyName.length === 0) {
                    return res.status(400).send({ "message": "Company Not Registered!" });
                }
                companyName = companyName[0]["companyName"];

                if (req.body.studentBatch === null || req.body.studentBatch === undefined || req.body.studentBatch === "") {
                    [companyHireData] = await db_connection.query(` select s.studentDept,s.studentSection,count(p.id) as totalHires
                from placementData p left join studentData s on p.studentId = s.id
                where companyId = ? group by s.studentDept,s.studentSection;`, [req.body.companyId]);

                    [companyHireData2] = await db_connection.query(`select s.studentRollNo, s.studentEmail, s.studentName,
                s.studentGender, s.studentBatch, s.studentDept, s.isHigherStudies, s.studentSection, 
                s.isPlaced, s.CGPA, p.ctc, p.jobRole, p.jobLocation, p.placementDate, p.isIntern, p.isPPO, p.isOnCampus, 
                p.isGirlsDrive, p.extraData from studentData s right join placementData p on 
                s.id = p.studentId where p.companyId = ?;`, [req.body.companyId]);
                } else {
                    [companyHireData] = await db_connection.query(` select s.studentDept,s.studentSection,count(p.id) as totalHires
                from placementData p left join studentData s on p.studentId = s.id
                where companyId = ? AND s.studentBatch = ? group by s.studentDept,s.studentSection`, [req.body.companyId, req.body.studentBatch]);

                    [companyHireData2] = await db_connection.query(`select s.studentRollNo, s.studentEmail, s.studentName,
                s.studentGender, s.studentBatch, s.studentDept, s.isHigherStudies, s.studentSection, 
                s.isPlaced, s.CGPA, p.ctc, p.jobRole, p.jobLocation, p.placementDate, p.isIntern, p.isPPO, p.isOnCampus, 
                p.isGirlsDrive, p.extraData from studentData s right join placementData p on 
                s.id = p.studentId where p.companyId = ? AND s.studentBatch = ?`, [req.body.companyId, req.body.studentBatch]);
                }

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({
                    "message": "Placement Data Fetched for " + companyName + "!",
                    "companyName": companyName,
                    "deptSectionWiseHires": companyHireData,
                    "allHiredStudents": companyHireData2
                });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getCompanyHireData - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        }
    ],


    getCompanyHireDatabyBatch: [
        /*
        JSON
        {
            "studentBatch": "<studentBatch>"
        }
        */
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || (req.body.userRole !== "1" && req.body.userRole !== "0" && req.body.userRole !== "2") ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
                (req.body.studentBatch === null || req.body.studentBatch === undefined || req.body.studentBatch === "" || isNaN(req.body.studentBatch))) {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData READ, placementData p READ, companyData c READ, studentData s READ`);

                if (req.body.userRole === "0" || req.body.userRole === "1") {

                    let [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);

                    if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }
                }
                else if (req.body.userRole === "2") {
                    let [student] = await db_connection.query(`SELECT * from studentData WHERE studentEmail = ?`, [req.body.userEmail]);

                    if (student.length === 0 || student[0]["studentAccountStatus"] !== "1") {
                        await db_connection.query(`UNLOCK TABLES`);
                        return res.status(401).send({ "message": "Access Restricted!" });
                    }

                }

                // extract section wise hire count for each company

                // [companyHireData] = await db_connection.query(`select p.companyId, c.companyName, p.ctc, p.jobRole, 
                //     count(p.id) as totalHires from placementData p left join companyData c 
                //     on p.companyId = c.id group by p.companyId, p.ctc, p.jobRole order by p.companyId;`);

                [companyHireData] = await db_connection.query(`select p.companyId, c.companyName, p.ctc, p.jobRole, s.studentSection, COUNT(p.id) AS totalHires FROM placementData p join companyData c on p.companyId=c.id join studentData s on p.studentId=s.id WHERE s.studentBatch = ? group by p.companyId, p.ctc, p.jobRole, s.studentSection order by p.companyId, p.ctc, p.jobRole, s.studentSection;`, [req.body.studentBatch]);

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({
                    "message": "Company Wise Placement Data Fetched!",
                    "companyHireData": companyHireData
                });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getCompanyHireData - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }

        }
    ],


    getAllStudentData: [
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
                (req.authorization_tier !== "0" && req.authorization_tier !== "1") ||
                req.body.batch === null || req.body.batch === undefined || req.body.batch === "") {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData s READ, companyData c READ, placementData p READ`);

                let [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);
                if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Access Restricted!" });
                }

                [students] = await db_connection.query(`select s.id as studentId, s.studentRollNo, s.studentEmail,
                s.studentName, s.studentGender, s.studentDept, s.studentBatch, s.studentSection, s.studentEmail,
                s.isHigherStudies, s.isPlaced, s.cgpa, s.studentAccountStatus,
                p.id as placementId, p.companyId, c.companyName, p.ctc, p.jobRole,
                p.jobLocation, p.placementDate, p.isIntern, p.isPPO, p.isOnCampus, p.isGirlsDrive,
                p.extraData from studentData s left join placementData p on s.id=p.studentId left join
                companyData c on p.companyId=c.id WHERE s.studentBatch = ? ORDER BY s.studentSection;`, [req.body.batch]);

                if (students.length === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(200).send({ "message": "No Student Data Found!", "students": students });
                }

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({
                    "message": "All Student Data Fetched!",
                    "students": students
                });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getAllStudentData - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        }
    ],

    getAllPlacedStudentsData: [
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" ||
                req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) ||
                (req.authorization_tier !== "0" && req.authorization_tier !== "1") ||
                req.body.batch === null || req.body.batch === undefined || req.body.batch === "") {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData s READ, companyData c READ, placementData p READ`);

                let [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);
                if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Access Restricted!" });
                }

                [students] = await db_connection.query(`select s.id as studentId, s.studentRollNo, s.studentEmail,
                s.studentName, s.studentGender, s.studentDept, s.studentBatch, s.studentSection, s.studentEmail,
                s.isHigherStudies, s.cgpa, s.studentAccountStatus,
                p.id as placementId, p.companyId, c.companyName, p.ctc, p.jobRole,
                p.jobLocation, p.placementDate, p.isIntern, p.isPPO, p.isOnCampus, p.isGirlsDrive,
                p.extraData from studentData s left join placementData p on s.id=p.studentId left join
                companyData c on p.companyId=c.id WHERE s.studentBatch = ? AND p.id IS NOT NULL ORDER BY s.studentSection, s.studentEmail;`, [req.body.batch]);

                if (students.length === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(200).send({ "message": "No Student Data Found!", "placementData": students });
                }

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({
                    "message": "All Student Data Fetched!",
                    "placementData": students
                });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getAllStudentData - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        }
    ],

    getTop5Placements: [
        webTokenValidator,
        async (req, res) => {
            if (req.body.userRole === null || req.body.userRole === undefined || req.body.userRole === "" || req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) || (req.body.userRole !== "1" && req.body.userRole !== "0")) {
                return res.status(400).send({ "message": "Access Restricted!" });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES managementData READ, studentData READ`);

                const [manager] = await db_connection.query(`SELECT accountStatus from managementData WHERE managerEmail = ?`, [req.body.userEmail]);

                if (manager.length === 0 || manager[0]["accountStatus"] !== "1") {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Access Restricted!" });
                }

                await db_connection.query(`LOCK TABLES placementData READ, studentData READ, companyData READ`);

                const [placements] = await db_connection.query(`SELECT studentName,studentRollNo,studentSection,studentDept,companyName,ctc,jobRole,jobLocation,placementDate,isIntern,isPPO,isOnCampus,isGirlsDrive,extraData from placementData INNER JOIN studentData ON placementData.studentId = studentData.id INNER JOIN companyData ON placementData.companyId = companyData.id ORDER BY ctc DESC LIMIT 10`);

                await db_connection.query(`UNLOCK TABLES`);

                return res.status(200).send({
                    "message": "Top 5 placements fetched!",
                    "placements": placements
                });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getTop5Placements - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        },
    ],

};