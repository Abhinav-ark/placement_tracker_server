const validator = require('validator');

module.exports = {
    isValidUserLoginReq: (req) => {
        if (req.body.userEmail === null || req.body.userEmail === undefined || req.body.userEmail === "" || !validator.isEmail(req.body.userEmail) || req.body.userPassword === null || req.body.userPassword === undefined || req.body.userPassword === "") {
            return true;
        }
        return false;
    } 
};