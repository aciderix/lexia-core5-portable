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
     * contentUrl uses HTTP so OSMF gets proper HTTPStatusEvent (code 200)
     * The proxy intercepts these requests and serves local files
     */
    public function handshake($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.HandshakeResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        $response->contentUrl = "https://student.mylexia.com/assets_a/";
        return $response;
    }
    
    /**
     * Called when the user enters a "teacher email" on the
     * "set up this computer" screen (Student/Parent flow).
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
        $response->contentUrl = "https://student.mylexia.com/assets_a/";
        $response->purpose = "course";
        $response->currentPhaseId = "a01";
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
     * Unit status - called when entering a level/unit
     * Returns UnitStatusResponseVO with empty progress for new student
     * Uses integer status (1 = in_progress) and null for empty fields
     * to prevent Flash from interpreting "" as a valid step ID
     */
    public function unitStatus($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.UnitStatusResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        $response->errorKindList = array();
        $response->isStruggling = false;
        $response->roundLeader = 0;
        $response->stepId = null;
        $response->unitId = isset($req->unitId) ? $req->unitId : "us_a01_bascateg_01";
        $response->studentId = 1;
        $response->status = 1;
        $response->progress = 0;
        $response->mastery = 0;
        $response->attempts = 0;
        $response->isComplete = false;
        $response->isPassed = false;
        $response->score = 0;
        $response->stepsCompleted = array();
        $response->currentStep = null;
        $response->skillData = new stdClass();
        $response->sessionData = new stdClass();
        $response->currentLevel = 1;
        $response->placementLevel = 1;
        $response->isPlacement = false;
        return $response;
    }
    
    /**
     * Save progress - called when the app wants to save student progress
     */
    public function saveProgress($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.ResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
    
    /**
     * Save unit status - called when exiting a unit
     */
    public function saveUnitStatus($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.ResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
    
    /**
     * Get student data - returns student progress data
     * Uses StudentResponseVO type for proper UI rendering
     */
    public function getStudentData($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.StudentResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
    
    /**
     * Log event - the app sends crash logs and telemetry
     */
    public function logEvent($req = null) {
        return true;
    }
    
    /**
     * Heartbeat - keep-alive ping
     */
    public function heartbeat($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.ResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
    
    /**
     * Logout - called when student logs out
     */
    public function logout($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.ResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
    
    /**
     * Get program data - returns program configuration
     * Uses ProgramDataResponseVO type for proper HUD rendering
     */
    public function getProgramData($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.ProgramDataResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        $response->programData = new stdClass();
        return $response;
    }
    
    /**
     * Submit answer - called when student answers a question
     */
    public function submitAnswer($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.ResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }

    /**
     * Step end - called when a step in a unit completes
     */
    public function stepEnd($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.StepEndResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }

    /**
     * Save unit data - called to persist unit state
     */
    public function saveUnitData($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.ResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }

    /**
     * Save warmup score - called after warmup game
     */
    public function saveWarmupScore($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.SaveWarmupScoreResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }

    /**
     * Reset student - admin reset
     */
    public function resetStudent($req = null) {
        $response = new stdClass();
        $response->_explicitType = 'com.lexialearning.lrs.api.ResponseVO';
        $response->errorCode = 0;
        $response->errorMessage = null;
        return $response;
    }
}
?>
