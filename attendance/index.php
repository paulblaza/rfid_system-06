<?php
// =================================================================
// SMART ATTENDANCE SYSTEM (ALL-IN-ONE)
// =================================================================
// Author: Your Name
// Version: 8.0 (Added Manual Log for Security)
// =================================================================

// --- 1. INITIALIZATION & SESSION ---
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// --- 2. CONFIGURATION ---
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', ''); // Default XAMPP password
define('DB_NAME', 'rfid_attendance');

// Set the timezone for all date/time functions
date_default_timezone_set('Asia/Manila');

// --- 3. DATABASE CONNECTION ---
try {
    $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($db->connect_errno) {
        throw new Exception("Failed to connect to MySQL: " . $db->connect_error);
    }
} catch (Exception $e) {
    // If connection fails, show a simple error page
    die("Database connection error: " . $e->getMessage());
}

// =================================================================
// --- 4. API ENDPOINT LOGIC (HANDLES JSON REQUESTS) ---
// =================================================================
// This block checks for API calls. If it finds one, it will
// send a JSON response and stop, preventing the HTML page
// from loading.

$api_action = $_REQUEST['action'] ?? '';

// --- API ACTION: log_attendance ---
// Called by the RFID Scanner (Node.js script)
if ($api_action === 'log_attendance') {
    header('Content-Type: application/json');
    $response = [];
    
    try {
        $rfid = $_POST['rfid_uid'] ?? '';
        if (empty($rfid)) {
            throw new Exception('RFID UID not provided.');
        }

        // 1. Find the student
        $stmt_student = $db->prepare(
            "SELECT s.id, s.name, s.student_photo_url, se.name as section_name 
             FROM students s 
             LEFT JOIN sections se ON s.section_id = se.id 
             WHERE s.student_rfid = ?"
        );
        $stmt_student->bind_param("s", $rfid);
        $stmt_student->execute();
        $result_student = $stmt_student->get_result();
        
        if ($student = $result_student->fetch_assoc()) {
            // --- STUDENT FOUND ---
            $student_id = $student['id'];
            $today = date('Y-m-d');
            $message = '';
            $status = '';

            // 2. Check last log for today
            $stmt_log = $db->prepare(
                "SELECT id, status FROM attendance_log 
                 WHERE student_id = ? AND DATE(timestamp_in) = ? 
                 ORDER BY timestamp_in DESC LIMIT 1"
            );
            $stmt_log->bind_param("is", $student_id, $today);
            $stmt_log->execute();
            $result_log = $stmt_log->get_result();
            
            if ($last_log = $result_log->fetch_assoc()) {
                // Log exists for today
                if ($last_log['status'] == 'in') {
                    // --- Logging OUT ---
                    $message = 'Time Out';
                    $status = 'out';
                    $stmt_update = $db->prepare("UPDATE attendance_log SET timestamp_out = NOW(), status = 'out' WHERE id = ?");
                    $stmt_update->bind_param("i", $last_log['id']);
                    $stmt_update->execute();
                } else {
                    // --- Logging IN (again) ---
                    $message = 'Time In';
                    $status = 'in';
                    $stmt_insert = $db->prepare("INSERT INTO attendance_log (student_id, timestamp_in, status) VALUES (?, NOW(), 'in')");
                    $stmt_insert->bind_param("i", $student_id);
                    $stmt_insert->execute();
                }
            } else {
                // --- First log of the day (Logging IN) ---
                $message = 'Time In';
                $status = 'in';
                $stmt_insert = $db->prepare("INSERT INTO attendance_log (student_id, timestamp_in, status) VALUES (?, NOW(), 'in')");
                $stmt_insert->bind_param("i", $student_id);
                $stmt_insert->execute();
            }

            // 3. Log to `last_scan_log` for the live feed
            $stmt_last_scan = $db->prepare(
                "INSERT INTO last_scan_log (student_name, section, student_photo_url, message, status, timestamp) 
                 VALUES (?, ?, ?, ?, ?, NOW())"
            );
            $stmt_last_scan->bind_param(
                "sssss", 
                $student['name'], 
                $student['section_name'], 
                $student['student_photo_url'], 
                $message,
                $status
            );
            $stmt_last_scan->execute();
            
            $response = ['status' => 'success', 'message' => $message, 'student' => $student['name']];
            
        } else {
            // --- STUDENT NOT FOUND ---
            $message = 'Invalid RFID';
            $status = 'error';
            
            // Log the invalid scan attempt
            $stmt_last_scan = $db->prepare(
                "INSERT INTO last_scan_log (student_name, section, student_photo_url, message, status, timestamp) 
                 VALUES (?, ?, ?, ?, ?, NOW())"
            );
            $placeholder_photo = 'https://placehold.co/200x200/e0e0e0/c00?text=INVALID';
            $student_name = 'Unknown RFID';
            $stmt_last_scan->bind_param("sssss", $student_name, $rfid, $placeholder_photo, $message, $status);
            $stmt_last_scan->execute();
            
            $response = ['status' => 'error', 'message' => 'Invalid RFID.'];
        }
        $stmt_student->close();
        
    } catch (Exception $e) {
        $response = ['status' => 'error', 'message' => $e->getMessage()];
    }
    
    echo json_encode($response);
    exit; // Stop script here
}

// --- API ACTION: get_new_logs ---
// Called by the JavaScript on the live_log.php page
if ($api_action === 'get_new_logs') {
    header('Content-Type: application/json');
    $response = [
        'logs' => [],
        'last_scan' => null,
        'new_timestamp' => 0
    ];

    try {
        $since_ts = (int)($_GET['since'] ?? 0);
        $response['new_timestamp'] = $since_ts;

        // 1. Get all logs newer than the 'since' timestamp for the feed
        $stmt_logs = $db->prepare(
            "SELECT *, UNIX_TIMESTAMP(timestamp) as unix_ts 
             FROM last_scan_log 
             WHERE UNIX_TIMESTAMP(timestamp) > ? 
             ORDER BY timestamp DESC"
        );
        $stmt_logs->bind_param("i", $since_ts);
        $stmt_logs->execute();
        $result_logs = $stmt_logs->get_result();
        
        $newest_ts = $since_ts;
        while ($row = $result_logs->fetch_assoc()) {
            $response['logs'][] = $row;
            if ($row['unix_ts'] > $newest_ts) {
                $newest_ts = $row['unix_ts'];
            }
        }
        $response['new_timestamp'] = $newest_ts;
        $stmt_logs->close();
        
        // 2. Get the absolute last scan for the main panel
        $result_last = $db->query("SELECT * FROM last_scan_log ORDER BY timestamp DESC LIMIT 1");
        if ($last = $result_last->fetch_assoc()) {
            $response['last_scan'] = $last;
            // Ensure the new_timestamp is at least as new as the last scan
            $last_scan_ts = strtotime($last['timestamp']);
            if ($last_scan_ts > $response['new_timestamp']) {
                $response['new_timestamp'] = $last_scan_ts;
            }
        }
    } catch (Exception $e) {
        $response = ['status' => 'error', 'message' => $e->getMessage()];
    }
    
    echo json_encode($response);
    exit; // Stop script here
}

// =================================================================
// --- 5. HTML PAGE LOGIC (CONTINUES IF NOT AN API CALL) ---
// =================================================================

// --- 5.1 HELPER FUNCTIONS ---

/**
 * Redirects to a different page.
 * @param string $page - The page to redirect to.
 * @param string $params - Optional URL parameters.
 */
function redirect($page, $params = '') {
    header("Location: index.php?page=$page" . $params);
    exit;
}

/**
 * Checks if a user is logged in and has the required role.
 * @param array $roles - An array of roles that are allowed to access the page.
 */
function auth_check($roles = []) {
    if (!isset($_SESSION['user_id'])) {
        redirect('login', '&error=' . urlencode('You must be logged in.'));
    }
    if (!empty($roles) && !in_array($_SESSION['user_role'], $roles)) {
        redirect('dashboard', '&error=' . urlencode('You do not have permission to view that page.'));
    }
}

/**
 * Gets the current user's role.
 * @return string|null - The user's role or null if not logged in.
 */
function get_current_role() {
    return $_SESSION['user_role'] ?? null;
}

/**
 * Gets the current user's ID.
 * @return int|null - The user's ID or null if not logged in.
 */
function get_current_user_id() {
    return $_SESSION['user_id'] ?? null;
}

/**
 * Displays a success or error message.
 */
function show_message() {
    // Use urldecode to properly display spaces and symbols
    if (isset($_GET['error'])) {
        echo '<div class="message error">' . htmlspecialchars(urldecode($_GET['error'])) . '</div>';
    }
    if (isset($_GET['success'])) {
        echo '<div class="message success">' . htmlspecialchars(urldecode($_GET['success'])) . '</div>';
    }
}

/**
 * Hashes a password.
 * @param string $password - The plaintext password.
 * @return string - The hashed password.
 */
function hash_password($password) {
    // Using a simple hash for this project.
    // A real-world project should use password_hash()
    return $password; // Storing as plain text per original request
    // return password_hash($password, PASSWORD_BCRYPT);
}

/**
 * Verifies a password.
 * @param string $password - The plaintext password.
 * @param string $hash - The hash from the database.
 * @return bool - True if the password matches, false otherwise.
 */
function verify_password($password, $hash) {
    // Plain text check
    return $password === $hash;
    // Hashed check
    // return password_verify($password, $hash);
}

// --- 5.2 GLOBAL VARIABLES (FOR HTML PAGE) ---
$page = $_GET['page'] ?? 'dashboard';
$action = $_POST['action'] ?? $_GET['action'] ?? null; // This is for FORMS, not the API
$login_error = '';
$current_role = get_current_role();
$current_user_id = get_current_user_id();

// --- 6. ACTION CONTROLLER (Handles HTML FORM submissions) ---
if ($action) {
    try {
        switch ($action) {
            
            // --- LOGIN/LOGOUT ACTIONS ---
            case 'login':
                $email = $_POST['email'];
                $password = $_POST['password'];
                
                $stmt = $db->prepare("SELECT id, name, password, role FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($user = $result->fetch_assoc()) {
                    if (verify_password($password, $user['password'])) {
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['user_name'] = $user['name'];
                        $_SESSION['user_role'] = $user['role'];
                        redirect('dashboard');
                    } else {
                        $login_error = "Invalid password.";
                    }
                } else {
                    $login_error = "No user found with that email.";
                }
                $stmt->close();
                break;

            case 'logout':
                session_destroy();
                redirect('login');
                break;

            // --- NEW: SECURITY MANUAL LOG ---
            case 'manual_log':
                auth_check(['security']); // Only security can do this
                $rfid = $_POST['rfid_uid'] ?? '';
                
                if (empty($rfid)) {
                    redirect('live_log', '&error=' . urlencode('RFID number cannot be empty.'));
                    break;
                }

                // --- This logic is copied from the API 'log_attendance' ---
                $stmt_student = $db->prepare(
                    "SELECT s.id, s.name, s.student_photo_url, se.name as section_name 
                     FROM students s 
                     LEFT JOIN sections se ON s.section_id = se.id 
                     WHERE s.student_rfid = ?"
                );
                $stmt_student->bind_param("s", $rfid);
                $stmt_student->execute();
                $result_student = $stmt_student->get_result();
                
                if ($student = $result_student->fetch_assoc()) {
                    // --- STUDENT FOUND ---
                    $student_id = $student['id'];
                    $today = date('Y-m-d');
                    $message = '';
                    $status = '';

                    $stmt_log = $db->prepare(
                        "SELECT id, status FROM attendance_log 
                         WHERE student_id = ? AND DATE(timestamp_in) = ? 
                         ORDER BY timestamp_in DESC LIMIT 1"
                    );
                    $stmt_log->bind_param("is", $student_id, $today);
                    $stmt_log->execute();
                    $result_log = $stmt_log->get_result();
                    
                    if ($last_log = $result_log->fetch_assoc()) {
                        if ($last_log['status'] == 'in') {
                            $message = 'Time Out';
                            $status = 'out';
                            $stmt_update = $db->prepare("UPDATE attendance_log SET timestamp_out = NOW(), status = 'out' WHERE id = ?");
                            $stmt_update->bind_param("i", $last_log['id']);
                            $stmt_update->execute();
                        } else {
                            $message = 'Time In';
                            $status = 'in';
                            $stmt_insert = $db->prepare("INSERT INTO attendance_log (student_id, timestamp_in, status) VALUES (?, NOW(), 'in')");
                            $stmt_insert->bind_param("i", $student_id);
                            $stmt_insert->execute();
                        }
                    } else {
                        $message = 'Time In';
                        $status = 'in';
                        $stmt_insert = $db->prepare("INSERT INTO attendance_log (student_id, timestamp_in, status) VALUES (?, NOW(), 'in')");
                        $stmt_insert->bind_param("i", $student_id);
                        $stmt_insert->execute();
                    }

                    // Log to `last_scan_log` for the live feed
                    $stmt_last_scan = $db->prepare(
                        "INSERT INTO last_scan_log (student_name, section, student_photo_url, message, status, timestamp) 
                         VALUES (?, ?, ?, ?, ?, NOW())"
                    );
                    $stmt_last_scan->bind_param(
                        "sssss", 
                        $student['name'], 
                        $student['section_name'], 
                        $student['student_photo_url'], 
                        $message,
                        $status
                    );
                    $stmt_last_scan->execute();
                    
                    // --- Redirect back with success message ---
                    redirect('live_log', '&success=' . urlencode($message . ' for ' . $student['name']));
                    
                } else {
                    // --- STUDENT NOT FOUND ---
                    $message = 'Invalid RFID';
                    $status = 'error';
                    
                    // Log the invalid scan attempt
                    $stmt_last_scan = $db->prepare(
                        "INSERT INTO last_scan_log (student_name, section, student_photo_url, message, status, timestamp) 
                         VALUES (?, ?, ?, ?, ?, NOW())"
                    );
                    $placeholder_photo = 'https://placehold.co/200x200/e0e0e0/c00?text=INVALID';
                    $student_name = 'Unknown RFID';
                    $stmt_last_scan->bind_param("sssss", $student_name, $rfid, $placeholder_photo, $message, $status);
                    $stmt_last_scan->execute();
                    
                    // --- Redirect back with error message ---
                    redirect('live_log', '&error=' . urlencode('Invalid RFID: ' . $rfid));
                }
                $stmt_student->close();
                break;
            // --- END OF NEW ACTION ---


            // --- ADMIN: USER MANAGEMENT ---
            case 'add_user':
                auth_check(['admin']);
                $name = $_POST['name'];
                $email = $_POST['email'];
                $password = hash_password($_POST['password']);
                $role = $_POST['role'];

                $stmt = $db->prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
                $stmt->bind_param("ssss", $name, $email, $password, $role);
                if ($stmt->execute()) {
                    redirect('users', '&success=' . urlencode('User added successfully.'));
                } else {
                    redirect('users', '&error=' . urlencode('Failed to add user. Email might already exist.'));
                }
                $stmt->close();
                break;

            case 'edit_user':
                auth_check(['admin']);
                $id = $_POST['id'];
                $name = $_POST['name'];
                $email = $_POST['email'];
                $role = $_POST['role'];

                if (!empty($_POST['password'])) {
                    // Update password
                    $password = hash_password($_POST['password']);
                    $stmt = $db->prepare("UPDATE users SET name = ?, email = ?, role = ?, password = ? WHERE id = ?");
                    $stmt->bind_param("ssssi", $name, $email, $role, $password, $id);
                } else {
                    // Don't update password
                    $stmt = $db->prepare("UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?");
                    $stmt->bind_param("sssi", $name, $email, $role, $id);
                }
                
                if ($stmt->execute()) {
                    redirect('users', '&success=' . urlencode('User updated successfully.'));
                } else {
                    redirect('users', '&error=' . urlencode('Failed to update user. Email might already exist.'));
                }
                $stmt->close();
                break;
                
            case 'delete_user':
                auth_check(['admin']);
                $id = $_GET['id'];
                $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $stmt->close();
                redirect('users', '&success=' . urlencode('User deleted.'));
                break;
                
            // --- ADMIN: STUDENT MANAGEMENT ---
            case 'add_student':
                auth_check(['admin']);
                
                $name = $_POST['name'];
                $student_rfid = $_POST['student_rfid'];
                $section_id = $_POST['section_id'];
                $parent_phone = $_POST['parent_phone'];
                $photo_url = 'https://placehold.co/200x200/eee/ccc?text=No+Photo'; // Default

                // Handle file upload
                if (isset($_FILES['student_photo']) && $_FILES['student_photo']['error'] == 0) {
                    $target_dir = "uploads/";
                    if (!is_dir($target_dir)) {
                        mkdir($target_dir, 0755, true);
                    }
                    $file_ext = strtolower(pathinfo($_FILES["student_photo"]["name"], PATHINFO_EXTENSION));
                    $target_file = $target_dir . uniqid(rand(), true) . '_' . basename($_FILES["student_photo"]["name"]);
                    $allowed_types = ['jpg', 'jpeg', 'png', 'gif'];

                    if (in_array($file_ext, $allowed_types)) {
                        if (move_uploaded_file($_FILES["student_photo"]["tmp_name"], $target_file)) {
                            $photo_url = $target_file;
                        } else {
                             redirect('students', '&error=' . urlencode('Failed to upload photo.'));
                             break;
                        }
                    } else {
                        redirect('students', '&error=' . urlencode('Invalid file type. Only JPG, JPEG, PNG, GIF allowed.'));
                        break;
                    }
                }

                $stmt = $db->prepare("INSERT INTO students (name, student_rfid, section_id, parent_phone, student_photo_url) VALUES (?, ?, ?, ?, ?)");
                $stmt->bind_param("ssiss", $name, $student_rfid, $section_id, $parent_phone, $photo_url);
                
                if ($stmt->execute()) {
                    redirect('students', '&success=' . urlencode('Student added successfully.'));
                } else {
                    redirect('students', '&error=' . urlencode('Failed to add student. RFID might already exist.'));
                }
                $stmt->close();
                break;

            case 'edit_student':
                auth_check(['admin']);
                
                $id = $_POST['id'];
                $name = $_POST['name'];
                $student_rfid = $_POST['student_rfid'];
                $section_id = $_POST['section_id'];
                $parent_phone = $_POST['parent_phone'];
                $photo_url = $_POST['existing_photo_url']; // Start with existing photo

                // Handle new file upload
                if (isset($_FILES['student_photo']) && $_FILES['student_photo']['error'] == 0) {
                    $target_dir = "uploads/";
                    if (!is_dir($target_dir)) {
                        mkdir($target_dir, 0755, true);
                    }
                    $file_ext = strtolower(pathinfo($_FILES["student_photo"]["name"], PATHINFO_EXTENSION));
                    $target_file = $target_dir . uniqid(rand(), true) . '_' . basename($_FILES["student_photo"]["name"]);
                    $allowed_types = ['jpg', 'jpeg', 'png', 'gif'];

                    if (in_array($file_ext, $allowed_types)) {
                        if (move_uploaded_file($_FILES["student_photo"]["tmp_name"], $target_file)) {
                            // Delete old photo if it's not the default placeholder
                            if ($photo_url && file_exists($photo_url) && strpos($photo_url, 'placehold.co') === false) {
                                unlink($photo_url);
                            }
                            $photo_url = $target_file; // Set to new photo
                        } else {
                             redirect('students', '&error=' . urlencode('Failed to upload new photo.'));
                             break;
                        }
                    } else {
                        redirect('students', '&error=' . urlencode('Invalid file type. Only JPG, JPEG, PNG, GIF allowed.'));
                        break;
                    }
                }
                
                $stmt = $db->prepare("UPDATE students SET name = ?, student_rfid = ?, section_id = ?, parent_phone = ?, student_photo_url = ? WHERE id = ?");
                $stmt->bind_param("ssissi", $name, $student_rfid, $section_id, $parent_phone, $photo_url, $id);
                
                if ($stmt->execute()) {
                    redirect('students', '&success=' . urlencode('Student updated successfully.'));
                } else {
                    redirect('students', '&error=' . urlencode('Failed to update student. RFID might already exist.'));
                }
                $stmt->close();
                break;

            case 'delete_student':
                auth_check(['admin']);
                $id = $_GET['id'];

                // First, get photo URL to delete the file
                $stmt = $db->prepare("SELECT student_photo_url FROM students WHERE id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($row = $result->fetch_assoc()) {
                    // Only delete if it's a real file and not the placeholder
                    if ($row['student_photo_url'] && file_exists($row['student_photo_url']) && strpos($row['student_photo_url'], 'placehold.co') === false) {
                        unlink($row['student_photo_url']);
                    }
                }
                $stmt->close();
                
                // Now delete the student record
                $stmt = $db->prepare("DELETE FROM students WHERE id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $stmt->close();
                redirect('students', '&success=' . urlencode('Student deleted successfully.'));
                break;

            // --- ADMIN: ASSIGN TEACHERS TO SUBJECTS ---
            case 'save_teacher_assignments':
                auth_check(['admin']);
                $section_id = $_POST['section_id'];
                $assignments = $_POST['assignments'] ?? []; // This will be an array like [subject_id => teacher_id]

                if (empty($section_id)) {
                    redirect('assign_teachers', '&error=' . urlencode('No section selected.'));
                    break;
                }

                // Prepare the update statement
                $stmt = $db->prepare("UPDATE section_subjects SET teacher_id = ? WHERE section_id = ? AND subject_id = ?");
                
                // --- CORRECTED FIX ---
                // Bind parameters ONCE, outside the loop.
                // We bind $bound_teacher_id (which will change)
                // We bind $section_id (which is constant)
                // We bind $bound_subject_id (which will change)
                // We use 'sii' (string, int, int) because teacher_id can be NULL, and NULL is handled correctly when bound as a string.
                
                $bound_teacher_id = null;
                $bound_subject_id = 0;
                // Note: We use the $section_id from the $_POST, which is already an integer.
                $stmt->bind_param("sii", $bound_teacher_id, $section_id, $bound_subject_id);
                
                foreach ($assignments as $subject_id => $teacher_id) {
                    // Inside the loop, we ONLY update the variables.
                    // We do NOT call bind_param again.
                    
                    if (!empty($teacher_id)) {
                        $bound_teacher_id = $teacher_id; // This will be a string like "2" or "15"
                    } else {
                        $bound_teacher_id = NULL; // This will be the actual NULL value
                    }
                    
                    $bound_subject_id = $subject_id; // This is the subject ID from the loop
                    
                    $stmt->execute();
                }
                $stmt->close();
                // --- END OF FIX ---
                
                redirect('assign_teachers', '&section_id=' . $section_id . '&success=' . urlencode('Teacher assignments saved.'));
                break;

            // --- ADMIN: ANNOUNCEMENTS (Parent Info) ---
            case 'save_announcement':
                auth_check(['admin']);
                $title = $_POST['title'];
                $content = $_POST['content'];
                
                $stmt = $db->prepare("INSERT INTO announcements (title, content, created_by) VALUES (?, ?, ?)");
                $stmt->bind_param("ssi", $title, $content, $current_user_id);
                if ($stmt->execute()) {
                    redirect('announcements', '&success=' . urlencode('Announcement posted.'));
                } else {
                    redirect('announcements', '&error=' . urlencode('Failed to post announcement.'));
                }
                $stmt->close();
                break;

            case 'delete_announcement':
                auth_check(['admin']);
                $id = $_GET['id'];
                $stmt = $db->prepare("DELETE FROM announcements WHERE id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $stmt->close();
                redirect('announcements', '&success=' . urlencode('Announcement deleted.'));
                break;

            // --- TEACHER: CLASS ATTENDANCE ---
            case 'save_class_attendance':
                auth_check(['teacher']);
                $subject_id = $_POST['subject_id'];
                $teacher_id = $current_user_id;
                $attendance_date = $_POST['attendance_date'];
                $students = $_POST['students'] ?? []; // Array of [student_id => status]

                if (empty($subject_id) || empty($attendance_date) || empty($students)) {
                    redirect('class_attendance', '&error=' . urlencode('Missing required data.'));
                    break;
                }

                // Use INSERT ... ON DUPLICATE KEY UPDATE to insert or update records
                $stmt = $db->prepare(
                    "INSERT INTO class_attendance (student_id, subject_id, teacher_id, attendance_date, status) 
                     VALUES (?, ?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE status = VALUES(status)"
                );

                foreach ($students as $student_id => $status) {
                    $stmt->bind_param("iiiss", $student_id, $subject_id, $teacher_id, $attendance_date, $status);
                    $stmt->execute();
                }
                $stmt->close();

                redirect('class_attendance', '&subject_id='.$subject_id.'&date='.$attendance_date.'&success=' . urlencode('Attendance saved successfully.'));
                break;

            // --- TEACHER/ADMIN: REPORTS ---
            case 'submit_report':
                auth_check(['admin', 'teacher']);
                $student_id = $_POST['student_id'];
                $type = $_POST['type'];
                $reason = $_POST['reason'];
                
                $stmt = $db->prepare("INSERT INTO reports (student_id, reported_by, reason, type) VALUES (?, ?, ?, ?)");
                $stmt->bind_param("iiss", $student_id, $current_user_id, $reason, $type);
                if ($stmt->execute()) {
                    redirect('reports', '&success=' . urlencode('Report submitted.'));
                } else {
                    redirect('reports', '&error=' . urlencode('Failed to submit report.'));
                }
                $stmt->close();
                break;

            case 'delete_report':
                auth_check(['admin']);
                $id = $_GET['id'];
                $stmt = $db->prepare("DELETE FROM reports WHERE id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $stmt->close();
                redirect('reports', '&success=' . urlencode('Report deleted.'));
                break;
                
        } // End of switch($action)
        
    } catch (Exception $e) {
        // Generic error handler for actions
        $page = 'dashboard'; // Default to a safe page
        redirect($page, '&error=' . urlencode('An unexpected error occurred: ' . $e->getMessage()));
    }
}


// --- 7. PAGE LOADING AND DATA FETCHER (Handles which page to show) ---

// If not logged in, force the login page, regardless of $page
if (!isset($_SESSION['user_id']) && $page != 'login') {
    $page = 'login';
}

// If logged in and trying to access login page, redirect to dashboard
if (isset($_SESSION['user_id']) && $page == 'login') {
    $page = 'dashboard';
    redirect('dashboard');
}

// Data container for the page
$page_data = [];

try {
    // This switch determines which page to load and what data to fetch
    switch ($page) {
        case 'dashboard':
            auth_check(['admin', 'teacher', 'security']);
            
            // Data for all roles
            $page_data['total_students'] = $db->query("SELECT COUNT(*) as c FROM students")->fetch_assoc()['c'];
            $page_data['total_teachers'] = $db->query("SELECT COUNT(*) as c FROM users WHERE role='teacher'")->fetch_assoc()['c'];
            
            // Data for security/admin
            if ($current_role != 'teacher') {
                $today = date('Y-m-d');
                $page_data['students_in'] = $db->query(
                    "SELECT COUNT(DISTINCT student_id) as c 
                     FROM attendance_log 
                     WHERE DATE(timestamp_in) = '$today' AND status = 'in'"
                )->fetch_assoc()['c'];
                
                $page_data['recent_logs'] = $db->query(
                    "SELECT l.*, s.name as student_name, se.name as section_name 
                     FROM attendance_log l
                     JOIN students s ON l.student_id = s.id
                     LEFT JOIN sections se ON s.section_id = se.id
                     WHERE DATE(l.timestamp_in) = '$today'
                     ORDER BY l.timestamp_in DESC
                     LIMIT 10"
                );
            }
            
            // Data for admin
            if ($current_role == 'admin') {
                $page_data['total_sections'] = $db->query("SELECT COUNT(*) as c FROM sections")->fetch_assoc()['c'];
                $page_data['total_subjects'] = $db->query("SELECT COUNT(*) as c FROM subjects")->fetch_assoc()['c'];
            }
            
            // Data for teachers
            if ($current_role == 'teacher') {
                // Get subjects taught by this teacher
                $stmt = $db->prepare(
                    "SELECT DISTINCT s.id, s.name, s.code 
                     FROM subjects s
                     JOIN section_subjects ss ON s.id = ss.subject_id
                     WHERE ss.teacher_id = ?
                     ORDER BY s.name"
                );
                $stmt->bind_param("i", $current_user_id);
                $stmt->execute();
                $page_data['teacher_subjects'] = $stmt->get_result();
                $stmt->close();
            }
            
            break;

        // --- ADMIN: USER MANAGEMENT ---
        case 'users':
            auth_check(['admin']);
            $page_data['users'] = $db->query("SELECT id, name, email, role FROM users ORDER BY name");
            break; 
            
        case 'students':
            auth_check(['admin']);
            $page_data['students'] = $db->query(
                "SELECT s.*, se.name as section_name 
                 FROM students s 
                 LEFT JOIN sections se ON s.section_id = se.id 
                 ORDER BY s.name"
            );
            $page_data['sections'] = $db->query("SELECT id, name FROM sections ORDER BY name");
            break;
   
        // --- ADMIN: ASSIGN TEACHERS ---
        case 'assign_teachers':
            auth_check(['admin']);
            $page_data['sections'] = $db->query("SELECT id, name FROM sections ORDER BY name");
            
            // Get all teachers for the dropdowns
            $page_data['teachers'] = $db->query("SELECT id, name FROM users WHERE role = 'teacher' ORDER BY name");
            
            $page_data['assigned_subjects'] = []; // Will hold subjects for the selected section
            $page_data['selected_section_name'] = '';
            
            if (!empty($_GET['section_id'])) {
                $section_id = (int)$_GET['section_id'];
                
                // Get selected section name
                $stmt = $db->prepare("SELECT name FROM sections WHERE id = ?");
                $stmt->bind_param("i", $section_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($row = $result->fetch_assoc()) {
                    $page_data['selected_section_name'] = $row['name'];
                }
                $stmt->close();
                
                // Get all subjects for this section, and the currently assigned teacher
                $stmt = $db->prepare(
                   "SELECT s.id as subject_id, s.name as subject_name, s.code as subject_code, ss.teacher_id
                    FROM section_subjects ss
                    JOIN subjects s ON ss.subject_id = s.id
                    WHERE ss.section_id = ?
                    ORDER BY s.name"
                );
                $stmt->bind_param("i", $section_id);
                $stmt->execute();
                $result = $stmt->get_result();
                while ($row = $result->fetch_assoc()) {
                    $page_data['assigned_subjects'][] = $row;
                }
                $stmt->close();
            }
            break;
            
        case 'announcements':
            auth_check(['admin']);
            $page_data['teachers'] = $db->query("SELECT id, name FROM users WHERE role IN ('admin', 'teacher') ORDER BY name");
            $page_data['announcements'] = $db->query(
                "SELECT a.*, u.name as author_name 
                 FROM announcements a 
                 JOIN users u ON a.created_by = u.id 
                 ORDER BY a.created_at DESC"
            );
            break;

        // --- ADMIN: VIEW SCHEDULES ---
        case 'schedules':
            auth_check(['admin']);
            $page_data['sections'] = $db->query("SELECT id, name FROM sections ORDER BY name");
            $page_data['subjects_by_section'] = [];

            if (!empty($_GET['section_id'])) {
                $section_id = (int)$_GET['section_id'];
                
                // Get selected section name
                $stmt = $db->prepare("SELECT name FROM sections WHERE id = ?");
                $stmt->bind_param("i", $section_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($row = $result->fetch_assoc()) {
                    $page_data['selected_section_name'] = $row['name'];
                }
                $stmt->close();

                // Get subjects and assigned teachers for that section
                $stmt = $db->prepare(
                   "SELECT s.name as subject_name, s.code as subject_code, u.name as teacher_name
                    FROM section_subjects ss
                    JOIN subjects s ON ss.subject_id = s.id
                    LEFT JOIN users u ON ss.teacher_id = u.id
                    WHERE ss.section_id = ?
                    ORDER BY s.name"
                );
                $stmt->bind_param("i", $section_id);
                $stmt->execute();
                $result = $stmt->get_result();
                while ($row = $result->fetch_assoc()) {
                    $page_data['subjects_by_section'][] = $row;
                }
                $stmt->close();
            }
            break;
            
        // --- TEACHER: CLASS ATTENDANCE ---
        case 'class_attendance':
            auth_check(['teacher']);
            
            // 1. Get subjects taught by this teacher
            $stmt = $db->prepare(
                "SELECT DISTINCT s.id, s.name, s.code
                 FROM subjects s
                 JOIN section_subjects ss ON s.id = ss.subject_id
                 WHERE ss.teacher_id = ?
                 ORDER BY s.name"
            );
            $stmt->bind_param("i", $current_user_id);
            $stmt->execute();
            $page_data['subjects'] = $stmt->get_result();
            $stmt->close();

            // 2. Check if a subject and date are selected
            $selected_subject_id = $_GET['subject_id'] ?? null;
            $selected_date = $_GET['date'] ?? date('Y-m-d');
            
            $page_data['students'] = [];
            $page_data['selected_subject_name'] = '';

            if ($selected_subject_id) {
                // 3. Get the name of the selected subject
                $stmt = $db->prepare("SELECT name, code FROM subjects WHERE id = ?");
                $stmt->bind_param("i", $selected_subject_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($row = $result->fetch_assoc()) {
                     $page_data['selected_subject_name'] = $row['name'] . ' (' . $row['code'] . ')';
                }
                $stmt->close();

                // 4. Get all students enrolled in this subject (via sections)
                // We also LEFT JOIN the attendance table to get their status for the selected date
                $stmt = $db->prepare(
                    "SELECT 
                        st.id, st.name, st.student_photo_url, se.name as section_name,
                        ca.status 
                     FROM students st
                     JOIN sections se ON st.section_id = se.id
                     JOIN section_subjects ss ON se.id = ss.section_id
                     LEFT JOIN class_attendance ca ON st.id = ca.student_id 
                                                 AND ca.subject_id = ? 
                                                 AND ca.attendance_date = ?
                     WHERE ss.subject_id = ? AND ss.teacher_id = ?
                     ORDER BY se.name, st.name"
                );
                $stmt->bind_param("ssii", $selected_subject_id, $selected_date, $selected_subject_id, $current_user_id);
                $stmt->execute();
                $page_data['students'] = $stmt->get_result();
                $stmt->close();
            }
            
            break;

        // --- ALL ROLES: REPORTS ---
        case 'reports':
            auth_check(['admin', 'teacher', 'security']);
            
            // Admins see all reports
            if ($current_role == 'admin') {
                $page_data['reports'] = $db->query(
                    "SELECT r.*, s.name as student_name, u.name as author_name 
                     FROM reports r
                     JOIN students s ON r.student_id = s.id
                     JOIN users u ON r.reported_by = u.id
                     ORDER BY r.timestamp DESC"
                );
            } else {
                // Teachers/Security only see their own reports
                $stmt = $db->prepare(
                    "SELECT r.*, s.name as student_name, u.name as author_name 
                     FROM reports r
                     JOIN students s ON r.student_id = s.id
                     JOIN users u ON r.reported_by = u.id
                     WHERE r.reported_by = ?
                     ORDER BY r.timestamp DESC"
                );
                $stmt->bind_param("i", $current_user_id);
                $stmt->execute();
                $page_data['reports'] = $stmt->get_result();
                $stmt->close();
            }
            
            // Get all students for the "New Report" dropdown
            $page_data['students'] = $db->query("SELECT id, name FROM students ORDER BY name");
            break;
            
        // --- SECURITY: LIVE LOG ---
        case 'live_log':
            auth_check(['security']);
            // This page will be updated via JavaScript (which now calls this same file)
            // No new data needed here, as the manual form is self-submitting.
            break;

        case 'login':
            // No data needed for login page
            break;
            
        default:
            // Page not found
            http_response_code(404);
            $page = '404';
            break;
    }
} catch (Exception $e) {
    // Generic error handler for page loading
    $page = 'dashboard';
    redirect('dashboard', '&error=' . urlencode('An error occurred loading page data: ' . $e->getMessage()));
}


// --- 8. RENDER THE HTML VIEW ---
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Attendance System</title>
    <!-- Simple CSS Reset -->
    <style>
        :root {
            --primary-color: #0052cc; /* STI Blue */
            --primary-dark: #003e99;
            --secondary-color: #ffc423; /* STI Yellow */
            --bg-color: #f4f7fc;
            --sidebar-bg: #ffffff;
            --card-bg: #ffffff;
            --text-color: #333;
            --text-light: #777;
            --border-color: #e0e0e0;
            --shadow: 0 4px 12px rgba(0,0,0,0.05);
            --shadow-lg: 0 10px 30px rgba(0,0,0,0.1);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
        }
        
        /* --- LOGIN PAGE --- */
        .login-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
        }
        .login-box {
            background: var(--card-bg);
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: var(--shadow-lg);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        .login-box h1 {
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }
        .login-box p {
            color: var(--text-light);
            margin-bottom: 2rem;
        }
        
        /* --- MAIN DASHBOARD LAYOUT --- */
        .dashboard-layout {
            display: flex;
            min-height: 100vh;
        }
        .sidebar {
            width: 260px;
            background: var(--sidebar-bg);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            padding: 1.5rem;
            flex-shrink: 0;
        }
        .sidebar-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .sidebar-header .logo {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary-color);
            text-decoration: none;
        }
        .sidebar-nav ul {
            list-style: none;
            flex-grow: 1;
        }
        .sidebar-nav li {
            margin-bottom: 0.5rem;
        }
        .sidebar-nav a {
            display: block;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            text-decoration: none;
            color: var(--text-light);
            font-weight: 500;
            transition: all 0.2s ease;
        }
        .sidebar-nav a:hover {
            background: var(--bg-color);
            color: var(--primary-color);
        }
        .sidebar-nav a.active {
            background: var(--primary-color);
            color: #ffffff;
            font-weight: 600;
        }
        .sidebar-footer {
            border-top: 1px solid var(--border-color);
            padding-top: 1rem;
        }
        .user-info {
            display: flex;
            align-items: center;
            padding: 0.5rem 0;
        }
        .user-info span {
            font-weight: 600;
            font-size: 0.9rem;
        }
        .logout-link {
            display: block;
            text-align: center;
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 600;
            padding: 0.5rem;
            border-radius: 6px;
        }
        .logout-link:hover {
            background: var(--bg-color);
        }
        
        .main-content {
            flex-grow: 1;
            padding: 2rem;
            overflow-y: auto;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }
        header h1 {
            font-size: 1.8rem;
            font-weight: 700;
        }
        
        /* --- COMPONENTS --- */
        .card {
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: var(--shadow);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 1.5rem;
        }
        .stat-card {
            text-align: center;
        }
        .stat-card h3 {
            font-size: 1rem;
            color: var(--text-light);
            font-weight: 500;
            margin-bottom: 0.5rem;
        }
        .stat-card .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
        }
        
        .form-group {
            margin-bottom: 1.25rem;
        }
        .form-group label {
            display: block;
            font-weight: 600;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }
        .form-control {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 1rem;
            transition: all 0.2s ease;
        }
        .form-control:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 2px rgba(0, 82, 204, 0.2);
        }
        textarea.form-control {
            min-height: 120px;
            resize: vertical;
        }
        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        .btn-primary {
            background: var(--primary-color);
            color: #ffffff;
        }
        .btn-primary:hover {
            background: var(--primary-dark);
        }
        .btn-secondary {
            background: var(--bg-color);
            color: var(--text-color);
            border: 1px solid var(--border-color);
        }
        .btn-secondary:hover {
            background: #e9eef7;
        }
        .btn-danger {
            background: #e53935;
            color: #ffffff;
        }
        .btn-danger-outline {
            background: transparent;
            color: #e53935;
            border: 1px solid #e53935;
            padding: 5px 10px;
            font-size: 0.9rem;
        }
        .btn-danger-outline:hover {
            background: #e53935;
            color: #fff;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        thead {
            background: var(--bg-color);
        }
        thead th {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-light);
            text-transform: uppercase;
        }
        tbody tr:last-child td {
            border-bottom: none;
        }
        tbody tr:hover {
            background-color: #fcfcfc;
        }
        
        .message {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-weight: 500;
        }
        .message.error {
            background: #ffebee;
            color: #c62828;
            border: 1px solid #ef9a9a;
        }
        .message.success {
            background: #e8f5e9;
            color: #2e7d32;
            border: 1px solid #a5d6a7;
        }
        
        /* --- ATTENDANCE PAGE --- */
        .attendance-filters {
            display: flex;
            gap: 1rem;
            align-items: flex-end;
        }
        .attendance-table img {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            margin-right: 10px;
            vertical-align: middle;
        }
        .attendance-table .status-select {
            padding: 0.5rem;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            font-size: 0.9rem;
        }
        
        /* --- LIVE LOG PAGE --- */
        #live-log-container {
            display: flex;
            gap: 1.5rem;
            /* Adjusted height to make space for the manual form */
            height: 70vh; 
        }
        #log-feed {
            flex: 1;
            overflow-y: auto;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: #fff;
        }
        #last-scan {
            flex: 0 0 350px;
            text-align: center;
        }
        #last-scan .card {
            height: 100%;
        }
        #last-scan-photo {
            width: 250px;
            height: 250px;
            border-radius: 50%;
            background: var(--bg-color);
            margin: 0 auto 1rem;
            border: 5px solid var(--border-color);
            object-fit: cover;
        }
        #last-scan-name {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }
        #last-scan-section {
            font-size: 1.1rem;
            color: var(--text-light);
            margin-bottom: 1rem;
        }
        #last-scan-message {
            font-size: 1.2rem;
            font-weight: 600;
            padding: 1rem;
            border-radius: 8px;
        }
        #last-scan-message.in {
            background: #e8f5e9;
            color: #2e7d32;
        }
        #last-scan-message.out {
            background: #fff3e0;
            color: #e65100;
        }
        #last-scan-message.error {
            background: #ffebee;
            color: #c62828;
        }
        .log-item {
            display: flex;
            align-items: center;
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        .log-item:last-child {
            border-bottom: none;
        }
        .log-item-photo {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            object-fit: cover;
            margin-right: 1rem;
        }
        .log-item-details {
            flex-grow: 1;
        }
        .log-item-name {
            font-weight: 600;
        }
        .log-item-section {
            font-size: 0.9rem;
            color: var(--text-light);
        }
        .log-item-time {
            font-weight: 600;
            font-size: 0.9rem;
        }
        .log-item-status.in {
            color: #2e7d32;
        }
        .log-item-status.out {
            color: #e65100;
        }
        .log-item-status.error {
            color: #c62828;
        }

        /* Responsive Design */
        @media (max-width: 1024px) {
            .grid-2 {
                grid-template-columns: 1fr;
            }
            #live-log-container {
                flex-direction: column;
                height: auto;
            }
            #last-scan {
                flex: 0 0 auto;
            }
        }
        
        @media (max-width: 768px) {
            .dashboard-layout {
                flex-direction: column;
            }
            .sidebar {
                width: 100%;
                height: auto;
                border-right: none;
                border-bottom: 1px solid var(--border-color);
            }
            .main-content {
                padding: 1.5rem;
            }
            header {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }
            .attendance-filters {
                flex-direction: column;
                align-items: stretch;
            }
        }

    </style>
</head>
<body>

    <?php if ($page == 'login'): ?>
        <!-- ============================================== -->
        <!-- ============= LOGIN PAGE ===================== -->
        <!-- ============================================== -->
        <div class="login-container">
            <div class="login-box">
                <img src="https://www.sti.edu/images/sti-logo.png" alt="STI Logo" width="150" style="margin-bottom: 1rem;">
                <h1>Welcome</h1>
                <p>Sign in to the Smart Attendance Dashboard</p>
                
                <?php if ($login_error): ?>
                    <div class="message error"><?php echo $login_error; ?></div>
                <?php endif; ?>
                
                <form action="index.php" method="POST">
                    <input type="hidden" name="action" value="login">
                    <div class="form-group" style="text-align: left;">
                        <label for="email">Email</label>
                        <input type="email" name="email" id="email" class="form-control" required>
                    </div>
                    <div class="form-group" style="text-align: left;">
                        <label for="password">Password</label>
                        <input type="password" name="password" id="password" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary" style="width: 100%;">Login</button>
                    </div>
                </form>
            </div>
        </div>

    <?php else: ?>
        <!-- ============================================== -->
        <!-- ============ MAIN DASHBOARD ================== -->
        <!-- ============================================== -->
        <div class="dashboard-layout">
            
            <!-- --- SIDEBAR --- -->
            <aside class="sidebar">
                <div class="sidebar-header">
                    <a href="index.php?page=dashboard" class="logo">SmartTap</a>
                </div>
                
                <nav class="sidebar-nav">
                    <ul>
                        <li><a href="index.php?page=dashboard" class="<?php if($page == 'dashboard') echo 'active'; ?>">Dashboard</a></li>
                        
                        <?php if ($current_role == 'admin'): ?>
                            <li><a href="index.php?page=users" class="<?php if($page == 'users') echo 'active'; ?>">User Management</a></li>
                            <li><a href="index.php?page=students" class="<?php if($page == 'students') echo 'active'; ?>">Student Management</a></li>
                            <li><a href="index.php?page=assign_teachers" class="<?php if($page == 'assign_teachers') echo 'active'; ?>">Assign Teachers</a></li>
                            <li><a href="index.php?page=schedules" class="<?php if($page == 'schedules') echo 'active'; ?>">View Section Info</a></li>
                            <li><a href="index.php?page=announcements" class="<?php if($page == 'announcements') echo 'active'; ?>">Announcements</a></li>
                        <?php endif; ?>
                        
                        <?php if ($current_role == 'teacher'): ?>
                            <li><a href="index.php?page=class_attendance" class="<?php if($page == 'class_attendance') echo 'active'; ?>">Class Attendance</a></li>
                        <?php endif; ?>
                        
                        <?php if ($current_role == 'security'): ?>
                            <li><a href="index.php?page=live_log" class="<?php if($page == 'live_log') echo 'active'; ?>">Live Attendance Log</a></li>
                        <?php endif; ?>
                        
                        <?php if ($current_role != 'security'): ?>
                             <li><a href="index.php?page=reports" class="<?php if($page == 'reports') echo 'active'; ?>">Reports</a></li>
                        <?php endif; ?>
                    </ul>
                </nav>
                
                <div class="sidebar-footer">
                    <div class="user-info">
                        <span><?php echo htmlspecialchars($_SESSION['user_name']); ?></span>
                    </div>
                    <a href="index.php?action=logout" class="logout-link">Logout</a>
                </div>
            </aside>
            
            <!-- --- MAIN CONTENT --- -->
            <main class="main-content">
                <header>
                    <h1>
                        <?php
                        // Page Titles
                        switch ($page) {
                            case 'dashboard': echo 'Dashboard'; break;
                            case 'users': echo 'User Management'; break;
                            case 'students': echo 'Student Management'; break;
                            case 'assign_teachers': echo 'Assign Teachers to Subjects'; break;
                            case 'schedules': echo 'View Section Info'; break;
                            case 'class_attendance': echo 'Class Attendance'; break;
                            case 'reports': echo 'Student Reports'; break;
                            case 'live_log': echo 'Live Attendance Log'; break;
                            case 'announcements': echo 'Announcements'; break;
                            case '404': echo 'Page Not Found'; break;
                            default: echo 'Dashboard'; break;
                        }
                        ?>
                    </h1>
                </header>
                
                <?php show_message(); ?>

                <!-- ============================================== -->
                <!-- =========== PAGE CONTENT START =============== -->
                <!-- ============================================== -->

                <?php // --- DASHBOARD PAGE --- ?>
                <?php if ($page == 'dashboard'): ?>
                    <div class="grid-3">
                        <div class="stat-card card">
                            <h3>Total Students</h3>
                            <div class="stat-number"><?php echo $page_data['total_students']; ?></div>
                        </div>
                        <div class="stat-card card">
                            <h3>Total Teachers</h3>
                            <div class="stat-number"><?php echo $page_data['total_teachers']; ?></div>
                        </div>
                        
                        <?php if ($current_role != 'teacher'): ?>
                        <div class="stat-card card">
                            <h3>Students In Today</h3>
                            <div class="stat-number"><?php echo $page_data['students_in']; ?></div>
                        </div>
                        <?php endif; ?>

                        <?php if ($current_role == 'admin'): ?>
                        <div class="stat-card card">
                            <h3>Total Sections</h3>
                            <div class="stat-number"><?php echo $page_data['total_sections']; ?></div>
                        </div>
                        <div class="stat-card card">
                            <h3>Total Subjects</h3>
                            <div class="stat-number"><?php echo $page_data['total_subjects']; ?></div>
                        </div>
                        <?php endif; ?>
                    </div>
                    
                    <?php if ($current_role != 'teacher'): ?>
                    <div class="card">
                        <h3>Recent Attendance Logs (Today)</h3>
                        <table>
                            <thead>
                                <tr>
                                    <th>Student</th>
                                    <th>Section</th>
                                    <th>Time In</th>
                                    <th>Time Out</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (isset($page_data['recent_logs']) && $page_data['recent_logs']->num_rows > 0): ?>
                                    <?php while($row = $page_data['recent_logs']->fetch_assoc()): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($row['student_name']); ?></td>
                                        <td><?php echo htmlspecialchars($row['section_name']); ?></td>
                                        <td><?php echo date('g:i A', strtotime($row['timestamp_in'])); ?></td>
                                        <td><?php echo $row['timestamp_out'] ? date('g:i A', strtotime($row['timestamp_out'])) : 'N/A'; ?></td>
                                        <td>
                                            <span class="log-item-status <?php echo $row['status']; ?>">
                                                <?php echo strtoupper($row['status']); ?>
                                            </span>
                                        </td>
                                    </tr>
                                    <?php endwhile; ?>
                                <?php else: ?>
                                    <tr>
                                        <td colspan="5" style="text-align: center;">No logs for today yet.</td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php endif; ?>

                    <?php if ($current_role == 'teacher'): ?>
                    <div class="card">
                        <h3>My Subjects</h3>
                        <table>
                            <thead>
                                <tr>
                                    <th>Subject Code</th>
                                    <th>Subject Name</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (isset($page_data['teacher_subjects']) && $page_data['teacher_subjects']->num_rows > 0): ?>
                                    <?php while($row = $page_data['teacher_subjects']->fetch_assoc()): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($row['code']); ?></td>
                                        <td><?php echo htmlspecialchars($row['name']); ?></td>
                                        <td>
                                            <a href="index.php?page=class_attendance&subject_id=<?php echo $row['id']; ?>&date=<?php echo date('Y-m-d'); ?>" class="btn btn-primary" style="padding: 5px 10px; font-size: 0.9rem;">
                                                Take Attendance
                                            </a>
                                        </td>
                                    </tr>
                                    <?php endwhile; ?>
                                <?php else: ?>
                                <tr>
                                    <td colspan="3" style="text-align: center;">You are not assigned to any subjects yet.</td>
                                </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php endif; ?>
                <?php endif; ?>
                
                
                <?php // --- ADMIN: USER MANAGEMENT --- ?>
                <?php if ($page == 'users' && $current_role == 'admin'): ?>
                    <div class="grid-2">
                        <div class="card">
                            <h3 id="form-title">Add New User</h3>
                            <form action="index.php" method="POST" id="user-form">
                                <input type="hidden" name="action" id="form-action" value="add_user">
                                <input type="hidden" name="id" id="user-id" value="0">
                                
                                <div class="form-group">
                                    <label for="name">Full Name</label>
                                    <input type="text" name="name" id="user-name" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label for="email">Email</label>
                                    <input type="email" name="email" id="user-email" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label for="password">Password</label>
                                    <input type="password" name="password" id="user-password" class="form-control">
                                    <small id="password-help">Leave blank to keep existing password when editing.</small>
                                </div>
                                <div class="form-group">
                                    <label for="role">Role</label>
                                    <select name="role" id="user-role" class="form-control">
                                        <option value="teacher">Teacher</option>
                                        <option value="admin">Admin</option>
                                        <option value="security">Security</option>
                                    </select>
                                </div>
                                <button type="submit" class="btn btn-primary">Save User</button>
                                <button type="button" class="btn btn-secondary" onclick="resetForm()">Cancel</button>
                            </form>
                        </div>
                        <div class="card">
                            <h3>Existing Users</h3>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Name</th>
                                        <th>Email</th>
                                        <th>Role</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php while($row = $page_data['users']->fetch_assoc()): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($row['name']); ?></td>
                                        <td><?php echo htmlspecialchars($row['email']); ?></td>
                                        <td><?php echo htmlspecialchars(ucfirst($row['role'])); ?></td>
                                        <td>
                                            <button class="btn btn-secondary" style="padding: 5px 10px; font-size: 0.9rem;" onclick="editUser(<?php echo htmlspecialchars(json_encode($row)); ?>)">
                                                Edit
                                            </button>
                                            <a href="index.php?action=delete_user&id=<?php echo $row['id']; ?>" class="btn btn-danger-outline" onclick="return confirm('Are you sure?')">
                                                Delete
                                            </a>
                                        </td>
                                    </tr>
                                    <?php endwhile; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <script>
                        function editUser(user) {
                            document.getElementById('form-title').innerText = 'Edit User';
                            document.getElementById('form-action').value = 'edit_user';
                            document.getElementById('user-id').value = user.id;
                            document.getElementById('user-name').value = user.name;
                            document.getElementById('user-email').value = user.email;
                            document.getElementById('user-role').value = user.role;
                            document.getElementById('user-password').value = '';
                            document.getElementById('user-password').placeholder = 'Leave blank to keep same password';
                            window.scrollTo(0, 0);
                        }
                        function resetForm() {
                            document.getElementById('form-title').innerText = 'Add New User';
                            document.getElementById('form-action').value = 'add_user';
                            document.getElementById('user-id').value = '0';
                            document.getElementById('user-form').reset();
                            document.getElementById('user-password').placeholder = '';
                        }
                    </script>
                <?php endif; ?>
                
                
                <?php // --- ADMIN: STUDENT MANAGEMENT --- ?>
                <?php if ($page == 'students' && $current_role == 'admin'): ?>
                    <div class="grid-2">
                        <div class="card">
                            <h3 id="student-form-title">Add New Student</h3>
                            <form action="index.php" method="POST" id="student-form" enctype="multipart/form-data">
                                <input type="hidden" name="action" id="student-form-action" value="add_student">
                                <input type="hidden" name="id" id="student-id" value="0">
                                <input type="hidden" name="existing_photo_url" id="existing-photo-url" value="">

                                <div class="form-group">
                                    <label for="name">Full Name</label>
                                    <input type="text" name="name" id="student-name" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label for="student_rfid">Student RFID</label>
                                    <input type="text" name="student_rfid" id="student-rfid" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label for="section_id">Section</label>
                                    <select name="section_id" id="student-section" class="form-control" required>
                                        <option value="">-- Select Section --</option>
                                        <?php while($row = $page_data['sections']->fetch_assoc()): ?>
                                        <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                                        <?php endwhile; ?>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="parent_phone">Parent's Phone (e.g., +639...)</label>
                                    <input type="text" name="parent_phone" id="student-phone" class="form-control">
                                </div>
                                <div class="form-group">
                                    <label for="student_photo">Student Photo</label>
                                    <input type="file" name="student_photo" id="student-photo" class="form-control">
                                    <small id="photo-help">Leave blank to keep existing photo when editing.</small>
                                </div>
                                <button type="submit" class="btn btn-primary">Save Student</button>
                                <button type="button" class="btn btn-secondary" onclick="resetStudentForm()">Cancel</button>
                            </form>
                        </div>
                        <div class="card">
                            <h3>Existing Students</h3>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Name</th>
                                        <th>Section</th>
                                        <th>RFID</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php while($row = $page_data['students']->fetch_assoc()): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($row['name']); ?></td>
                                        <td><?php echo htmlspecialchars($row['section_name'] ?? 'N/A'); ?></td>
                                        <td><?php echo htmlspecialchars($row['student_rfid']); ?></td>
                                        <td>
                                            <button class="btn btn-secondary" style="padding: 5px 10px; font-size: 0.9rem;" onclick="editStudent(<?php echo htmlspecialchars(json_encode($row)); ?>)">
                                                Edit
                                            </button>
                                            <a href="index.php?action=delete_student&id=<?php echo $row['id']; ?>" class="btn btn-danger-outline" onclick="return confirm('Are you sure?')">
                                                Delete
                                            </a>
                                        </td>
                                    </tr>
                                    <?php endwhile; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <script>
                        function editStudent(student) {
                            document.getElementById('student-form-title').innerText = 'Edit Student';
                            document.getElementById('student-form-action').value = 'edit_student';
                            document.getElementById('student-id').value = student.id;
                            document.getElementById('student-name').value = student.name;
                            document.getElementById('student-rfid').value = student.student_rfid;
                            document.getElementById('student-section').value = student.section_id;
                            document.getElementById('student-phone').value = student.parent_phone;
                            document.getElementById('existing-photo-url').value = student.student_photo_url;
                            document.getElementById('student-photo').value = ''; // Clear file input
                            window.scrollTo(0, 0);
                        }
                        function resetStudentForm() {
                            document.getElementById('student-form-title').innerText = 'Add New Student';
                            document.getElementById('student-form-action').value = 'add_student';
                            document.getElementById('student-id').value = '0';
                            document.getElementById('student-form').reset();
                        }
                    </script>
                <?php endif; ?>
                
                
                <!-- ============================================== -->
                <!-- ===== MODIFIED: ADMIN PAGE (ASSIGN TEACHERS) ==== -->
                <!-- ============================================== -->
                <?php if ($page == 'assign_teachers' && $current_role == 'admin'): ?>
                    <div class="grid-2">
                        <div class="card">
                            <h3>1. Select Section</h3>
                            <form action="index.php" method="GET">
                                <input type="hidden" name="page" value="assign_teachers">
                                <div class="form-group">
                                    <label for="section_id">Select a section to manage its teachers:</label>
                                    <select name="section_id" id="section_id" class="form-control" onchange="this.form.submit()">
                                        <option value="">-- Select Section --</option>
                                        <?php 
                                        $current_section_id = $_GET['section_id'] ?? 0;
                                        $page_data['sections']->data_seek(0); // Reset pointer
                                        while ($row = $page_data['sections']->fetch_assoc()): 
                                        ?>
                                            <option value="<?php echo $row['id']; ?>" <?php if ($current_section_id == $row['id']) echo 'selected'; ?>>
                                                <?php echo htmlspecialchars($row['name']); ?>
                                            </option>
                                        <?php endwhile; ?>
                                    </select>
                                </div>
                            </form>
                        </div>

                        <div class="card">
                            <h3>2. Assign Teachers</h3>
                            <?php if (empty($current_section_id)): ?>
                                <p>Please select a section from the left to see its subject list.</p>
                            <?php else: ?>
                                <form action="index.php" method="POST">
                                    <input type="hidden" name="action" value="save_teacher_assignments">
                                    <input type="hidden" name="section_id" value="<?php echo $current_section_id; ?>">
                                    
                                    <h4>Subjects for <?php echo htmlspecialchars($page_data['selected_section_name']); ?></h4>
                                    <p>Select a teacher for each subject in this section.</p>
                                    
                                    <!-- New Table Layout -->
                                    <table style="margin-top: 1.5rem;">
                                        <thead>
                                            <tr>
                                                <th>Subject</th>
                                                <th style="width: 50%;">Assigned Teacher</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php 
                                            // Cache teachers data to avoid re-querying in loop
                                            $teacher_list = [];
                                            if (isset($page_data['teachers']) && $page_data['teachers']->num_rows > 0) {
                                                $page_data['teachers']->data_seek(0);
                                                while ($teacher_row = $page_data['teachers']->fetch_assoc()) {
                                                    $teacher_list[] = $teacher_row;
                                                }
                                            }

                                            if (empty($page_data['assigned_subjects'])):
                                            ?>
                                                <tr>
                                                    <td colspan="2" style="text-align: center;">
                                                        No subjects are assigned to this section yet.
                                                    </td>
                                                </tr>
                                            <?php else: 
                                                foreach ($page_data['assigned_subjects'] as $subject): 
                                                    $subject_id = $subject['subject_id'];
                                                    $current_teacher_id = $subject['teacher_id'];
                                            ?>
                                                <tr>
                                                    <td>
                                                        <strong><?php echo htmlspecialchars($subject['subject_name']); ?></strong><br>
                                                        <small style="color: var(--text-light);"><?php echo htmlspecialchars($subject['subject_code']); ?></small>
                                                    </td>
                                                    <td>
                                                        <div class="form-group" style="margin-bottom: 0;">
                                                            <!-- The name attribute is an array: assignments[subject_id] = teacher_id -->
                                                            <select name="assignments[<?php echo $subject_id; ?>]" class="form-control">
                                                                <option value="">-- Unassigned --</option>
                                                                <?php foreach ($teacher_list as $teacher): ?>
                                                                    <option value="<?php echo $teacher['id']; ?>" <?php if ($current_teacher_id == $teacher['id']) echo 'selected'; ?>>
                                                                        <?php echo htmlspecialchars($teacher['name']); ?>
                                                                    </option>
                                                                <?php endforeach; ?>
                                                            </select>
                                                        </div>
                                                    </td>
                                                </tr>
                                            <?php 
                                                endforeach; 
                                            endif;
                                            ?>
                                        </tbody>
                                    </table>
                                    
                                    <br>
                                    <button type="submit" class="btn btn-primary">Save Assignments</button>
                                </form>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
                
                
                <?php // --- ADMIN: VIEW SCHEDULES/SECTION INFO --- ?>
                <?php if ($page == 'schedules' && $current_role == 'admin'): ?>
                    <div class="grid-2">
                        <div class="card">
                            <h3>1. Select Section</h3>
                            <form action="index.php" method="GET">
                                <input type="hidden" name="page" value="schedules">
                                <div class="form-group">
                                    <label for="section_id">Select a section to view its info:</label>
                                    <select name="section_id" id="section_id" class="form-control" onchange="this.form.submit()">
                                        <option value="">-- Select Section --</option>
                                        <?php 
                                        $current_section_id = $_GET['section_id'] ?? 0;
                                        $page_data['sections']->data_seek(0); // Reset pointer
                                        while ($row = $page_data['sections']->fetch_assoc()): 
                                        ?>
                                            <option value="<?php echo $row['id']; ?>" <?php if ($current_section_id == $row['id']) echo 'selected'; ?>>
                                                <?php echo htmlspecialchars($row['name']); ?>
                                            </option>
                                        <?php endwhile; ?>
                                    </select>
                                </div>
                            </form>
                        </div>

                        <div class="card">
                            <h3>Subject & Teacher List</h3>
                            <?php if (empty($current_section_id)): ?>
                                <p>Please select a section from the left.</p>
                            <?php else: ?>
                                <h4>Viewing: <?php echo htmlspecialchars($page_data['selected_section_name']); ?></h4>
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Subject Code</th>
                                            <th>Subject Name</th>
                                            <th>Assigned Teacher</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($page_data['subjects_by_section'])): ?>
                                            <tr><td colspan="3" style="text-align: center;">No subjects assigned to this section.</td></tr>
                                        <?php else: ?>
                                            <?php foreach ($page_data['subjects_by_section'] as $row): ?>
                                                <tr>
                                                    <td><?php echo htmlspecialchars($row['subject_code']); ?></td>
                                                    <td><?php echo htmlspecialchars($row['subject_name']); ?></td>
                                                    <td><?php echo htmlspecialchars($row['teacher_name'] ?? 'N/A'); ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>


                <?php // --- ADMIN: ANNOUNCEMENTS --- ?>
                <?php if ($page == 'announcements' && $current_role == 'admin'): ?>
                    <div class="grid-2">
                        <div class="card">
                            <h3>Post New Announcement</h3>
                            <form action="index.php" method="POST">
                                <input type="hidden" name="action" value="save_announcement">
                                <div class="form-group">
                                    <label for="title">Title</label>
                                    <input type="text" name="title" id="title" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label for="content">Message</label>
                                    <textarea name="content" id="content" class="form-control" required></textarea>
                                </div>
                                <button type="submit" class="btn btn-primary">Post Announcement</button>
                            </form>
                        </div>
                        <div class="card">
                            <h3>Posted Announcements</h3>
                            <?php if (isset($page_data['announcements']) && $page_data['announcements']->num_rows > 0): ?>
                                <?php while($row = $page_data['announcements']->fetch_assoc()): ?>
                                    <div style="border-bottom: 1px solid var(--border-color); padding-bottom: 1rem; margin-bottom: 1rem;">
                                        <strong><?php echo htmlspecialchars($row['title']); ?></strong>
                                        <p style="margin: 0.5rem 0;"><?php echo nl2br(htmlspecialchars($row['content'])); ?></p>
                                        <small style="color: var(--text-light);">
                                            Posted by <?php echo htmlspecialchars($row['author_name']); ?> on <?php echo date('M d, Y g:i A', strtotime($row['created_at'])); ?>
                                        </small>
                                        <a href="index.php?action=delete_announcement&id=<?php echo $row['id']; ?>" class="btn btn-danger-outline" style="float: right;" onclick="return confirm('Are you sure?')">
                                            Delete
                                        </a>
                                    </div>
                                <?php endwhile; ?>
                            <?php else: ?>
                                <p>No announcements posted yet.</p>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
                

                <?php // --- TEACHER: CLASS ATTENDANCE --- ?>
                <?php if ($page == 'class_attendance' && $current_role == 'teacher'): ?>
                    <div class="card">
                        <form action="index.php" method="GET">
                            <input type="hidden" name="page" value="class_attendance">
                            <div class="attendance-filters">
                                <div class="form-group" style="flex: 2;">
                                    <label for="subject_id">Select Subject</label>
                                    <select name="subject_id" id="subject_id" class="form-control">
                                        <option value="">-- Select a subject --</option>
                                        <?php 
                                        $current_subject_id = $_GET['subject_id'] ?? 0;
                                        if (isset($page_data['subjects']) && $page_data['subjects']->num_rows > 0):
                                            while($row = $page_data['subjects']->fetch_assoc()): 
                                        ?>
                                            <option value="<?php echo $row['id']; ?>" <?php if($current_subject_id == $row['id']) echo 'selected'; ?>>
                                                <?php echo htmlspecialchars($row['name']); ?> (<?php echo htmlspecialchars($row['code']); ?>)
                                            </option>
                                        <?php 
                                            endwhile; 
                                        endif;
                                        ?>
                                    </select>
                                </div>
                                <div class="form-group" style="flex: 1;">
                                    <label for="date">Date</label>
                                    <input type="date" name="date" id="date" class="form-control" value="<?php echo $_GET['date'] ?? date('Y-m-d'); ?>">
                                </div>
                                <button type="submit" class="btn btn-primary" style="height: fit-content;">Load Students</button>
                            </div>
                        </form>
                    </div>

                    <?php if (!empty($page_data['students']) && $page_data['students']->num_rows > 0): ?>
                    <div class="card">
                        <h3>Marking Attendance for: <?php echo htmlspecialchars($page_data['selected_subject_name']); ?></h3>
                        <p>Date: <?php echo htmlspecialchars($_GET['date'] ?? date('Y-m-d')); ?></p>
                        
                        <form action="index.php" method="POST">
                            <input type="hidden" name="action" value="save_class_attendance">
                            <input type="hidden" name="subject_id" value="<?php echo $current_subject_id; ?>">
                            <input type="hidden" name="attendance_date" value="<?php echo $_GET['date'] ?? date('Y-m-d'); ?>">
                            
                            <table class="attendance-table" style="margin-top: 1.5rem;">
                                <thead>
                                    <tr>
                                        <th>Student</th>
                                        <th>Section</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php 
                                    $current_section = '';
                                    while($row = $page_data['students']->fetch_assoc()): 
                                        if ($current_section != $row['section_name']) {
                                            $current_section = $row['section_name'];
                                            echo '<tr><td colspan="3" style="background: var(--bg-color); font-weight: 700;">' . htmlspecialchars($current_section) . '</td></tr>';
                                        }
                                    ?>
                                    <tr>
                                        <td>
                                            <img src="<?php echo htmlspecialchars($row['student_photo_url']); ?>" alt="Photo" class="log-item-photo">
                                            <?php echo htmlspecialchars($row['name']); ?>
                                        </td>
                                        <td><?php echo htmlspecialchars($row['section_name']); ?></td>
                                        <td>
                                            <select name="students[<?php echo $row['id']; ?>]" class="status-select">
                                                <option value="present" <?php if($row['status'] == 'present') echo 'selected'; ?>>Present</option>
                                                <option value="absent" <?php if($row['status'] == 'absent') echo 'selected'; ?>>Absent</option>
                                                <option value="late" <?php if($row['status'] == 'late') echo 'selected'; ?>>Late</option>
                                            </select>
                                        </td>
                                    </tr>
                                    <?php endwhile; ?>
                                </tbody>
                            </table>
                            <br>
                            <button type="submit" class="btn btn-primary">Save Attendance</button>
                        </form>
                    </div>
                    <?php elseif (!empty($current_subject_id)): ?>
                    <div class="card">
                        <h3>Marking Attendance for: <?php echo htmlspecialchars($page_data['selected_subject_name']); ?></h3>
                        <p>No students are enrolled in this subject.</p>
                    </div>
                    <?php endif; ?>
                <?php endif; ?>
                
                
                <?php // --- REPORTS PAGE --- ?>
                <?php if ($page == 'reports' && $current_role != 'security'): ?>
                    <div class="grid-2">
                        <div class="card">
                            <h3>Submit New Report</h3>
                            <form action="index.php" method="POST">
                                <input type="hidden" name="action" value="submit_report">
                                <div class="form-group">
                                    <label for="student_id">Student</label>
                                    <select name="student_id" id="student_id" class="form-control" required>
                                        <option value="">-- Select Student --</option>
                                        <?php if (isset($page_data['students']) && $page_data['students']->num_rows > 0): ?>
                                            <?php while($row = $page_data['students']->fetch_assoc()): ?>
                                            <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                                            <?php endwhile; ?>
                                        <?php endif; ?>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="type">Report Type</label>
                                    <select name="type" id="type" class="form-control" required>
                                        <option value="absentee">Absenteeism</option>
                                        <option value="proxy">Proxy Attendance</option>
                                        <option value="other">Other</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="reason">Reason / Details</label>
                                    <textarea name="reason" id="reason" class="form-control" required></textarea>
                                </div>
                                <button type="submit" class="btn btn-primary">Submit Report</button>
                            </form>
                        </div>
                        <div class="card">
                            <h3>
                                <?php echo ($current_role == 'admin') ? 'All Submitted Reports' : 'My Submitted Reports'; ?>
                            </h3>
                            <?php if (isset($page_data['reports']) && $page_data['reports']->num_rows > 0): ?>
                                <?php while($row = $page_data['reports']->fetch_assoc()): ?>
                                    <div style="border-bottom: 1px solid var(--border-color); padding-bottom: 1rem; margin-bottom: 1rem;">
                                        <strong style="font-size: 1.1rem;"><?php echo htmlspecialchars($row['student_name']); ?></strong>
                                        <span style="background: #eee; padding: 3px 8px; border-radius: 6px; font-size: 0.9rem; font-weight: 600; margin-left: 10px;">
                                            <?php echo htmlspecialchars(ucfirst($row['type'])); ?>
                                        </span>
                                        
                                        <?php if ($current_role == 'admin'): ?>
                                        <a href="index.php?action=delete_report&id=<?php echo $row['id']; ?>" class="btn btn-danger-outline" style="float: right;" onclick="return confirm('Are you sure?')">
                                            Delete
                                        </a>
                                        <?php endif; ?>
                                        
                                        <p style="margin: 0.5rem 0;"><?php echo nl2br(htmlspecialchars($row['reason'])); ?></p>
                                        <small style="color: var(--text-light);">
                                            Reported by <?php echo htmlspecialchars($row['author_name']); ?> on <?php echo date('M d, Y g:i A', strtotime($row['timestamp'])); ?>
                                        </small>
                                    </div>
                                <?php endwhile; ?>
                            <?php else: ?>
                                <p>No reports found.</p>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>


                <?php // --- SECURITY: LIVE LOG --- ?>
                <?php if ($page == 'live_log' && $current_role == 'security'): ?>
                    
                    <!-- ================== NEW MANUAL ENTRY FORM ================== -->
                    <div class="card">
                        <h3>Manual Entry</h3>
                        <p>If the scanner is not working, enter the RFID number manually below and press "Log Entry".</p>
                        <form action="index.php" method="POST">
                            <input type="hidden" name="action" value="manual_log">
                            <div class="form-group" style="margin-top: 1rem;">
                                <label for="rfid_uid_manual">RFID Number</label>
                                <input type="text" name="rfid_uid" id="rfid_uid_manual" class="form-control" placeholder="Enter RFID number..." required autofocus>
                            </div>
                            <button type="submit" class="btn btn-primary" style="width: 100%;">Log Entry</button>
                        </form>
                    </div>
                    <!-- ================== END NEW FORM ================== -->

                    <div id="live-log-container">
                        <div id="last-scan">
                            <div class="card">
                                <h3>Last Scan</h3>
                                <img src="https://placehold.co/250x250/f4f7fc/ccc?text=Waiting+for+tap" alt="Student Photo" id="last-scan-photo">
                                <h2 id="last-scan-name">No Student Scanned</h2>
                                <p id="last-scan-section">Waiting for RFID tap...</p>
                                <div id="last-scan-message"></div>
                            </div>
                        </div>
                        <div id="log-feed" class="card" style="padding: 0;">
                            <!-- Log items will be prepended here by JavaScript -->
                        </div>
                    </div>
                    
                    <script>
                        // Function to update the "Last Scan" panel
                        function updateLastScan(log) {
                            const photoEl = document.getElementById('last-scan-photo');
                            const nameEl = document.getElementById('last-scan-name');
                            const sectionEl = document.getElementById('last-scan-section');
                            const messageEl = document.getElementById('last-scan-message');
                            
                            photoEl.src = log.student_photo_url || 'https://placehold.co/250x250/f4f7fc/ccc?text=No+Photo';
                            nameEl.innerText = log.student_name;
                            sectionEl.innerText = log.section;
                            
                            messageEl.innerText = log.message;
                            messageEl.className = log.status; // 'in', 'out', or 'error'
                        }
                        
                        // Function to add a new item to the log feed
                        function addLogItem(log) {
                            const feedEl = document.getElementById('log-feed');
                            const item = document.createElement('div');
                            item.className = 'log-item';
                            
                            item.innerHTML = `
                                <img src="${log.student_photo_url || 'https://placehold.co/45x45/f4f7fc/ccc?text=No+Photo'}" alt="Photo" class="log-item-photo">
                                <div class="log-item-details">
                                    <div class="log-item-name">${log.student_name}</div>
                                    <div class="log-item-section">${log.section}</div>
                                </div>
                                <div class="log-item-time">
                                    ${new Date(log.timestamp).toLocaleTimeString()}
                                    <span class="log-item-status ${log.status}">${log.status.toUpperCase()}</span>
                                </div>
                            `;
                            
                            // Prepend (add to top)
                            feedEl.insertBefore(item, feedEl.firstChild);
                        }

                        // Function to fetch new logs
                        async function fetchLogs() {
                            try {
                                // Get the timestamp of the very last log we received
                                const lastTimestamp = document.getElementById('log-feed').dataset.lastTimestamp || 0;
                                
                                // --- THIS IS THE MODIFIED LINE ---
                                // It now calls index.php instead of api.php
                                const response = await fetch(`index.php?action=get_new_logs&since=${lastTimestamp}`);
                                // --- END MODIFICATION ---
                                
                                if (!response.ok) {
                                    console.error("Failed to fetch logs");
                                    return;
                                }
                                
                                const data = await response.json();
                                
                                if (data.logs && data.logs.length > 0) {
                                    // Update the timestamp to the newest log's time
                                    document.getElementById('log-feed').dataset.lastTimestamp = data.new_timestamp;
                                    
                                    // Update the "Last Scan" panel with the most recent log
                                    updateLastScan(data.logs[0]);
                                    
                                    // Add all new logs to the feed in reverse (oldest new first)
                                    data.logs.reverse().forEach(log => {
                                        addLogItem(log);
G                                    });
                                }
                                
                                // Update "Last Scan" if there's only a `last_scan` entry but no new logs
                                // And only if the feed is currently empty
                                if (data.last_scan && (!data.logs || data.logs.length === 0) && document.getElementById('log-feed').children.length === 0) {
                                    updateLastScan(data.last_scan);
                                }
                                
                            } catch (error) {
                                console.error("Error fetching logs:", error);
                            }
                        }
                        
                        // Poll for new logs every 2 seconds
                        setInterval(fetchLogs, 2000);
                        
                        // Fetch immediately on page load
                        document.addEventListener('DOMContentLoaded', fetchLogs);
                    </script>
                <?php endif; ?>
                
                <?php // --- 404 PAGE --- ?>
                <?php if ($page == '404'): ?>
                    <div class="card" style="text-align: center;">
                        <h2>404 - Page Not Found</h2>
                        <p>Sorry, the page you are looking for does not exist.</p>
                        <a href="index.php?page=dashboard" class="btn btn-primary">Go to Dashboard</a>
                    </div>
                <?php endif; ?>

                <!-- ============================================== -->
                <!-- ============ PAGE CONTENT END ================ -->
                <!-- ============================================== -->
                
            </main>
        </div>
    <?php endif; ?>

</body>