<?php
/**
 * AMFClient - Mock service for Lexia Core5
 * 
 * This class provides the methods that the Lexia Core5 Flex application
 * calls via AMFPHP remoting. The _explicitType property tells AMFPHP
 * which ActionScript class to use when serializing the response,
 * preventing Error #1034 (Type Coercion failed).
 */
class AMFClient {
    
    /**
     * Handshake response - first call after CONNECT
     * Returns HandshakeResponseVO with no error
     */
    public function handshake($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.HandshakeResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
    
    /**
     * Called when the user enters a "teacher email" on the
     * "set up this computer" screen (Student/Parent flow).
     * Returns TeacherResponseVO - must have isAuthenticated=true
     * and a siteId/siteName for the flow to continue to verifySiteId/login.
     */
    public function getCustomerFromTeacher($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.TeacherResponseVO';
        $response->siteId = "1";
        $response->siteName = "Portable Site";
        $response->isAuthenticated = true;
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
    
    /**
     * Called after getCustomerFromTeacher to verify the site ID.
     * Returns VerifySiteIdResponseVO with isValid=true.
     */
    public function verifySiteId($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.VerifySiteIdResponseVO';
        $response->siteName = "Portable Site";
        $response->isValid = true;
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
    
    /**
     * Login response - called after handshake
     * Returns LoginResponseVO with a fake auth token
     */
    public function login($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.LoginResponseVO';
        $response->authToken = "bypass-token-" . uniqid();
        $response->studentId = 1;
        $response->personName = "Admin Portable";
        $response->language = "en-US";
        $response->region = "us";
        $response->purpose = "course";
        $response->currentPhaseId = "1";
        $response->currentUnitIdList = array();
        $response->isAuditMode = false;
        $response->isUnhidePassword = false;
        $response->irtForm = "";
        $response->startUnit = "";
        $response->classList = null;
        $response->grade = "Grade 2";
        $response->teacher = "Teacher";
        $response->showWarmup = false;
        $response->secondsSinceLastLogin = 0;
        $response->warmupHighScore = 0;
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
    
    /**
     * Log event - the app sends crash logs and telemetry
     * Just return true to acknowledge
     */
    public function logEvent($req = null) {
        return true;
    }
    
    /**
     * Generic catch-all for any other methods the app might call
     */
    public function __call($name, $arguments) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.ResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
}
?>
