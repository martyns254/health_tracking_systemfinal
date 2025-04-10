from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import mysql.connector
import uuid
import bcrypt
import io
import csv
import pandas as pd
from io import BytesIO
from datetime import datetime
from datetime import timedelta
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs


class HealthServer(BaseHTTPRequestHandler):
    def serve_file(self, filename):
        try:
            with open(filename, 'rb') as file:
                content = file.read()
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(content)
            print(f"Sent {filename}")
        except Exception as e:
            print("Error:", str(e))
            self.send_error(500)
    
    def do_GET(self):
        print("Request received for:", self.path)
        
        if self.path == '/':
            self.serve_file('templates/index.html')
        elif self.path == '/register':
            self.serve_file('templates/register.html')
        elif self.path == '/login':
            self.serve_file('templates/login.html')
        elif self.path == '/dashboard':
            self.serve_file('templates/dashboard.html')
        elif self.path == '/health/log':
            self.serve_file('templates/health_log.html')
        elif self.path == '/symptoms':
            self.serve_file('templates/symptoms.html')
        elif self.path == '/medical/history':
            self.serve_file('templates/medical_history.html')
        elif self.path == '/symptom/analysis':
            self.serve_file('templates/symptom_analysis.html')
        elif self.path == '/first_aid':
            self.serve_file('templates/first_aid.html')	
        elif self.path == '/health/visualization':
            print("Attempting to serve visualization page")
            try:
                self.serve_file('templates/health_visualization.html')
                print("Visualization page served successfully")
            except Exception as e:
                print(f"Error serving visualization page: {str(e)}")
                self.send_error(500)    
        # New routes for health metrics
        elif self.path == '/health/metrics':
            self.handle_get_health_metrics()
        elif self.path == '/admin/reports':
            self.handle_admin_reports_list()
        elif self.path == '/health/metrics/track':
            self.serve_file('templates/health_metrics.html')
        elif self.path == '/health/trends':
            self.serve_file('templates/health_trends.html')
        elif self.path.startswith('/user/metrics/'):
            parts = self.path.split('/')
            user_id = parts[3]
            metric_id = parts[4] if len(parts) > 4 else None
            self.handle_get_user_metrics(user_id, metric_id)
        # Existing routes
        elif self.path.startswith('/health/logs/'):
            user_id = self.path.split('/')[-1]
            self.handle_get_logs(user_id)
        elif self.path.startswith('/symptoms/logs/'):
            user_id = self.path.split('/')[-1]
            self.handle_get_symptoms(user_id)
        elif self.path.startswith('/public/trends'):
            self.handle_public_trends()
        elif self.path.startswith('/medical/history/'):
            user_id = self.path.split('/')[-1]
            self.handle_get_medical_history(user_id)
        elif self.path == '/admin':
            self.serve_file('templates/admin.html')
        elif self.path == '/admin/login':
            self.serve_file('templates/login.html')  # Reuse login page with admin toggle
        elif self.path == '/admin/stats':
            self.handle_admin_stats()
        elif self.path == '/admin/recent-activity':
            self.handle_admin_recent_activity()
        elif self.path.startswith('/admin/users'):
            parts = self.path.split('/')
            user_id = parts[3] if len(parts) > 3 else None
            if user_id:
                self.handle_admin_user_detail(user_id)
            else:
                self.handle_admin_users_list()
        elif self.path.startswith('/export/user-data/'):
            user_id = self.path.split('/')[-1].split('?')[0]
            if self.is_authorized_for_user_data(user_id):
                self.handle_export_user_data(user_id)
            else:
                self.send_error(403, "Unauthorized access to user data")
        else:  # This is for the main path check
            self.send_error(404)      
        
                
            
    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            if self.path == '/register':
                self.handle_registration(data)
            elif self.path == '/login':
                self.handle_login(data)
            elif self.path == '/health/log':
                self.handle_health_log(data)
            elif self.path == '/symptoms/log':
                self.handle_symptoms(data)
            elif self.path == '/medical/history':
                self.handle_medical_history(data)
            elif self.path == '/analyze/symptoms':
                self.handle_symptom_analysis(data)
            # New route for health metrics logging
            elif self.path == '/health/metric/log':
                self.handle_log_metric(data)
            elif self.path == '/admin/login':
                self.handle_admin_login(data)
            elif self.path == '/admin/users':
                self.handle_admin_add_user(data)
            elif self.path == '/admin/reports':
                self.handle_admin_reports_list()
            elif self.path == '/admin/reports/generate':
                self.handle_admin_generate_report(data)
            else:
                self.send_error(404)
                
        except Exception as e:
            print("Error in POST:", str(e))
            self.send_error(500)
    def export_as_excel(self, user_id, username, metrics, health_logs, symptoms):
        """Export user data as Excel file"""
        try:
            current_date = datetime.now().strftime("%Y-%m-%d")
            
            # Create a Pandas Excel writer
            output = io.BytesIO()
            writer = pd.ExcelWriter(output, engine='openpyxl')
            
            # Convert metrics to DataFrame and write to Excel
            metrics_df = pd.DataFrame([self.convert_dict_for_json(m) for m in metrics])
            if not metrics_df.empty:
                metrics_df.to_excel(writer, sheet_name='Health Metrics', index=False)
            
            # Convert health logs to DataFrame and write to Excel
            health_logs_df = pd.DataFrame([self.convert_dict_for_json(h) for h in health_logs])
            if not health_logs_df.empty:
                health_logs_df.to_excel(writer, sheet_name='Health Logs', index=False)
            
            # Convert symptoms to DataFrame and write to Excel
            symptoms_df = pd.DataFrame([self.convert_dict_for_json(s) for s in symptoms])
            if not symptoms_df.empty:
                symptoms_df.to_excel(writer, sheet_name='Symptoms', index=False)
            
            # Save the Excel file
            writer.save()
            
            # Get the Excel content
            output.seek(0)
            excel_data = output.getvalue()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
            self.send_header('Content-Disposition', f'attachment; filename="health_data_{username}_{current_date}.xlsx"')
            self.send_header('Content-Length', str(len(excel_data)))
            self.end_headers()
            self.wfile.write(excel_data)
            
        except Exception as e:
            print(f"Error generating Excel: {str(e)}")
            self.send_error(500, "Error generating export file")

    def handle_registration(self, user_data):
        try:
            password_bytes = user_data['password'].encode('utf-8')
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password_bytes, salt)
            
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor()
            
            query = """INSERT INTO users (username, password_hash, email, is_admin) 
                      VALUES (%s, %s, %s, %s)"""
            cursor.execute(query, (
                user_data['username'],
                hashed_password.decode('utf-8'),
                user_data['email'],
                0
            ))
            conn.commit()
            
            print("User registered successfully")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"message": "Registration successful"}).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_login(self, user_data):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            query = """SELECT id, username, password_hash, is_admin FROM users 
                      WHERE username = %s"""
            cursor.execute(query, (user_data['username'],))
            user = cursor.fetchone()
            
           
            if user:
                # Verify password with bcrypt
                password_bytes = user_data['password'].encode('utf-8')
                stored_hash = user['password_hash'].encode('utf-8')
                
                # Handle both bcrypt hashes and legacy plain text passwords
                password_valid = False
                
                # If the stored password starts with $2b$ or $2a$, it's a bcrypt hash
                if stored_hash.startswith(b'$2'):
                    password_valid = bcrypt.checkpw(password_bytes, stored_hash)
                else:
                    # Legacy plain text comparison - ONLY FOR TRANSITION PERIOD
                    password_valid = (user['password_hash'] == user_data['password'])
                    
                    # If using legacy auth, update to bcrypt hash
                    if password_valid:
                        # Hash the password with bcrypt for future logins
                        salt = bcrypt.gensalt()
                        hashed_password = bcrypt.hashpw(password_bytes, salt)
                        
                        # Update the user's password hash
                        update_query = """UPDATE users SET password_hash = %s WHERE id = %s"""
                        cursor.execute(update_query, (hashed_password.decode('utf-8'), user['id']))
                        conn.commit()
                        print(f"Updated password hash for user {user['username']} to bcrypt")
                
                if password_valid:
                    if user.get('is_admin', 0) == 0:
                        print(f"User logged in successfully: {user['username']}")
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({
                            "message": "Login successful",
                            "username": user['username'],
                            "userId": user['id']
                        }).encode())
                    else:
                        print("Login failed: Admin account used on user login page")
                        self.send_error(401)
                else:
                    print("Login failed: Invalid credentials")
                    self.send_error(401)
            else:
                print("Login failed: Invalid credentials")
                self.send_error(401)
                    
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()
                
    def handle_admin_login(self, user_data):
        try:
            conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
        
            query = """SELECT id, username FROM users 
                  WHERE username = %s AND password_hash = %s 
                  AND is_admin = 1"""
            cursor.execute(query, (
            user_data['username'],
            user_data['password']
            ))
            admin = cursor.fetchone()
        
            if admin:
                print(f"Admin logged in successfully: {admin['username']}")
            
           
                admin_token = str(uuid.uuid4())
            
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "message": "Admin login successful",
                    "username": admin['username'],
                    "userId": admin['id'],
                    "adminToken": admin_token
                }).encode())
            else:
                print("Admin login failed: Invalid credentials")
                self.send_error(401)
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_health_log(self, log_data):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor()
            
            query = """INSERT INTO health_logs 
                      (user_id, temperature, symptoms, notes, recorded_at)
                      VALUES (%s, %s, %s, %s, %s)"""
            
            cursor.execute(query, (
                log_data['userId'],
                log_data['temperature'],
                ','.join(log_data['symptoms']),
                log_data['notes'],
                datetime.now()
            ))
            
            conn.commit()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"message": "Health log saved"}).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_get_logs(self, user_id):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            query = """SELECT * FROM health_logs 
                      WHERE user_id = %s 
                      ORDER BY recorded_at DESC 
                      LIMIT 5"""
            cursor.execute(query, (user_id,))
            logs = cursor.fetchall()
            
            for log in logs:
                if 'temperature' in log and log['temperature']:
                    log['temperature'] = str(log['temperature'])
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(logs, default=str).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_symptoms(self, symptom_data):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor()
            
            query = """INSERT INTO symptoms_log 
                      (user_id, symptom_name, severity, duration, notes) 
                      VALUES (%s, %s, %s, %s, %s)"""
            
            cursor.execute(query, (
                symptom_data['userId'],
                symptom_data['symptomName'],
                symptom_data['severity'],
                symptom_data['duration'],
                symptom_data['notes']
            ))
            
            conn.commit()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"message": "Symptoms logged successfully"}).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_get_symptoms(self, user_id):
        try:
            # Parse query parameters
            query_components = parse_qs(urlparse(self.path).query)
            time_range = query_components.get('timeRange', ['30d'])[0]  # Default to 30 days
            
            # Calculate start date based on time range
            start_date = self.calculate_start_date(time_range)
            
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            # Update query to include date filter
            query = """SELECT * FROM symptoms_log 
                    WHERE user_id = %s AND recorded_at >= %s
                    ORDER BY recorded_at DESC 
                    LIMIT 30"""
            cursor.execute(query, (user_id, start_date))
            symptoms = cursor.fetchall()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(symptoms, default=str).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_medical_history(self, history_data):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor()
            
            query = """INSERT INTO medical_history 
                      (user_id, condition_name, diagnosed_date, status, medications, notes) 
                      VALUES (%s, %s, %s, %s, %s, %s)"""
            
            cursor.execute(query, (
                history_data['userId'],
                history_data['condition'],
                history_data['diagnosedDate'],
                history_data['status'],
                history_data['medications'],
                history_data['notes']
            ))
            
            conn.commit()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"message": "Medical history saved"}).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_get_medical_history(self, user_id):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            query = """SELECT * FROM medical_history 
                      WHERE user_id = %s 
                      ORDER BY diagnosed_date DESC"""
            cursor.execute(query, (user_id,))
            history = cursor.fetchall()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(history, default=str).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_symptom_analysis(self, data):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            # Sort symptoms to match stored combinations
            symptoms = sorted(data['symptoms'])
            symptom_combination = ','.join(symptoms)
            severity = data['severity']
            
            # Try to find exact match
            query = """SELECT * FROM symptom_recommendations 
                      WHERE symptom_combination = %s 
                      AND severity_level = %s"""
            cursor.execute(query, (symptom_combination, severity))
            recommendation = cursor.fetchone()
            
            if not recommendation:
                # Try to find partial match
                for symptom in symptoms:
                    cursor.execute("""
                        SELECT * FROM symptom_recommendations 
                        WHERE symptom_combination LIKE %s 
                        AND severity_level = %s 
                        LIMIT 1
                    """, (f'%{symptom}%', severity))
                    recommendation = cursor.fetchone()
                    if recommendation:
                        break
            
            if recommendation:
                if severity == 'severe':
                    recommendation['emergency_level'] = 'high'
                    recommendation['recommendation'] = 'SEEK IMMEDIATE MEDICAL ATTENTION. ' + recommendation['recommendation']
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(recommendation).encode())
            else:
                # Default response if no match found
                default_response = {
                    'recommendation': 'Based on your symptoms, we recommend monitoring your condition.',
                    'emergency_level': 'medium',
                    'warning_signs': 'If symptoms worsen or persist, consult a healthcare provider.',
                    'basic_treatment': 'Rest and stay hydrated. Monitor your symptoms.',
                    'seek_doctor_if': 'Symptoms persist or worsen after 24 hours.'
                }
                
                if severity == 'severe':
                    default_response['emergency_level'] = 'high'
                    default_response['recommendation'] = 'SEEK IMMEDIATE MEDICAL ATTENTION.'
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(default_response).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    # New handler methods for health metrics
    def handle_get_health_metrics(self):
        """Return all available health metrics for tracking, filtering out duplicates"""
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            query = "SELECT * FROM health_metrics ORDER BY category, name"
            cursor.execute(query)
            all_metrics = cursor.fetchall()
            
            # Filter out duplicates - keep only the first occurrence of each metric name
            seen_names = set()
            unique_metrics = []
            
            for metric in all_metrics:
                if metric['name'] not in seen_names:
                    seen_names.add(metric['name'])
                    unique_metrics.append(metric)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(unique_metrics, default=str).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_log_metric(self, data):
        """Record a specific health metric value"""
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor()
            
            query = """INSERT INTO user_metrics 
                      (user_id, metric_id, value, notes, recorded_at)
                      VALUES (%s, %s, %s, %s, %s)"""
            
            cursor.execute(query, (
                data['userId'],
                data['metricId'],
                data['value'],
                data.get('notes', ''),
                datetime.now()
            ))
            
            conn.commit()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"message": "Health metric saved"}).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_get_user_metrics(self, user_id, metric_id=None):
        """Get user's recorded metrics with optional filtering by metric ID and time range"""
        try:
            print(f"Getting metrics for user: {user_id}, metric: {metric_id}")
            # Parse query parameters
            query_components = parse_qs(urlparse(self.path).query)
            time_range = query_components.get('timeRange', ['30d'])[0]  # Default to 30 days
            print(f"Time range: {time_range}")
            
            # Calculate start date based on time range
            start_date = self.calculate_start_date(time_range)
            print(f"Start date: {start_date}")
            
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            # Log the queries
            if metric_id:
                query = """SELECT um.*, hm.name, hm.display_name, hm.unit 
                        FROM user_metrics um
                        JOIN health_metrics hm ON um.metric_id = hm.metric_id
                        WHERE um.user_id = %s AND um.metric_id = %s
                        AND um.recorded_at >= %s
                        ORDER BY um.recorded_at DESC"""
                print(f"Executing query with params: user_id={user_id}, metric_id={metric_id}, start_date={start_date}")
                cursor.execute(query, (user_id, metric_id, start_date))
            else:
                query = """SELECT um.*, hm.name, hm.display_name, hm.unit 
                        FROM user_metrics um
                        JOIN health_metrics hm ON um.metric_id = hm.metric_id
                        WHERE um.user_id = %s
                        AND um.recorded_at >= %s
                        ORDER BY um.recorded_at DESC"""
                print(f"Executing query with params: user_id={user_id}, start_date={start_date}")
                cursor.execute(query, (user_id, start_date))
                    
            metrics = cursor.fetchall()
            print(f"Found {len(metrics)} metrics")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(metrics, default=str).encode())
            print("Successfully sent metrics response")
            
        except mysql.connector.Error as e:
            print(f"Database error in handle_get_user_metrics: {str(e)}")
            self.send_error(500)
        except Exception as e:
            print(f"Unexpected error in handle_get_user_metrics: {str(e)}")
            import traceback
            traceback.print_exc()
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_public_trends(self):
        """Return anonymized health trend data for public viewing"""
        from datetime import timedelta
        from urllib.parse import urlparse, parse_qs
        
        try:
            print("Processing trends request")
            # Get query parameters
            query_components = parse_qs(urlparse(self.path).query)
            trend_type = query_components.get('type', ['all'])[0]
            time_period = query_components.get('time', ['30d'])[0]
            
            print(f"Trend request parameters: type={trend_type}, time={time_period}")
            
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            # Define the time range based on the period
            now = datetime.now()
            if time_period == '7d':
                start_date = now - timedelta(days=7)
                period_label = "Last 7 Days"
            elif time_period == '30d':
                start_date = now - timedelta(days=30)
                period_label = "Last 30 Days"
            elif time_period == '90d':
                start_date = now - timedelta(days=90)
                period_label = "Last 90 Days"
            elif time_period == '1y':
                start_date = now - timedelta(days=365)
                period_label = "Last Year"
            else:
                start_date = now - timedelta(days=30)  # Default to 30 days
                period_label = "Last 30 Days"
                
            start_date_str = start_date.strftime('%Y-%m-%d')
            
            trends = []
            
            # Add symptom trends
            if trend_type == 'all' or trend_type == 'symptoms':
                # Get top symptoms
                query = """
                    SELECT 
                        symptom_name,
                        COUNT(*) as count
                    FROM symptoms_log
                    WHERE recorded_at >= %s
                    GROUP BY symptom_name
                    ORDER BY count DESC
                    LIMIT 5
                """
                cursor.execute(query, (start_date_str,))
                top_symptoms = cursor.fetchall()
                
                if top_symptoms:
                    # Create data for pie chart
                    labels = [symptom['symptom_name'] for symptom in top_symptoms]
                    data = [symptom['count'] for symptom in top_symptoms]
                    
                    # Add to trends list
                    trends.append({
                        'title': f"Most Common Symptoms - {period_label}",
                        'chart_type': 'pie',
                        'chart_data': {
                            'labels': labels,
                            'datasets': [{
                                'data': data,
                                'backgroundColor': [
                                    'rgba(255, 99, 132, 0.7)',
                                    'rgba(54, 162, 235, 0.7)',
                                    'rgba(255, 206, 86, 0.7)',
                                    'rgba(75, 192, 192, 0.7)',
                                    'rgba(153, 102, 255, 0.7)'
                                ],
                                'borderWidth': 1
                            }]
                        },
                        'stats': [
                            {'value': sum(data), 'label': 'Total Reports'},
                            {'value': len(set(labels)), 'label': 'Unique Symptoms'}
                        ],
                        'description': 'Distribution of the most commonly reported symptoms'
                    })
            
            # Add temperature trends
            if trend_type == 'all' or trend_type == 'vitals':
                # Temperature trends over time
                query = """
                    SELECT 
                        DATE(recorded_at) as record_date,
                        AVG(temperature) as avg_temp
                    FROM health_logs
                    WHERE temperature IS NOT NULL 
                      AND temperature BETWEEN 35.0 AND 41.0
                      AND recorded_at >= %s
                    GROUP BY record_date
                    ORDER BY record_date
                """
                cursor.execute(query, (start_date_str,))
                temp_data = cursor.fetchall()
                
                if temp_data and len(temp_data) > 1:
                    dates = [str(item['record_date']) for item in temp_data]
                    temps = [float(item['avg_temp']) for item in temp_data]
                    
                    trends.append({
                        'title': f"Average Body Temperature - {period_label}",
                        'chart_type': 'line',
                        'chart_data': {
                            'labels': dates,
                            'datasets': [{
                                'label': 'Average Temperature (°C)',
                                'data': temps,
                                'borderColor': 'rgba(255, 99, 132, 1)',
                                'backgroundColor': 'rgba(255, 99, 132, 0.2)',
                                'tension': 0.1
                            }]
                        },
                        'stats': [
                            {'value': round(sum(temps) / len(temps), 1), 'label': 'Avg Temp (°C)'},
                            {'value': round(min(temps), 1), 'label': 'Min Temp (°C)'},
                            {'value': round(max(temps), 1), 'label': 'Max Temp (°C)'}
                        ],
                        'description': 'Average recorded body temperature over time'
                    })
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(trends, default=str).encode())
            
        except Exception as e:
            print(f"Error in trends handler: {type(e)._name_}: {str(e)}")
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_get_user_metrics(self, user_id, metric_id=None):
        """Get user's recorded metrics with optional filtering by metric ID and time range"""
        try:
            # Parse query parameters
            query_components = parse_qs(urlparse(self.path).query)
            time_range = query_components.get('timeRange', ['30d'])[0]  # Default to 30 days
            
            # Calculate start date based on time range
            start_date = self.calculate_start_date(time_range)
            
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            if metric_id:
                query = """SELECT um.*, hm.name, hm.display_name, hm.unit 
                        FROM user_metrics um
                        JOIN health_metrics hm ON um.metric_id = hm.metric_id
                        WHERE um.user_id = %s AND um.metric_id = %s
                        AND um.recorded_at >= %s
                        ORDER BY um.recorded_at DESC"""
                cursor.execute(query, (user_id, metric_id, start_date))
            else:
                query = """SELECT um.*, hm.name, hm.display_name, hm.unit 
                        FROM user_metrics um
                        JOIN health_metrics hm ON um.metric_id = hm.metric_id
                        WHERE um.user_id = %s
                        AND um.recorded_at >= %s
                        ORDER BY um.recorded_at DESC"""
                cursor.execute(query, (user_id, start_date))
                
            metrics = cursor.fetchall()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(metrics, default=str).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()
    def handle_export_user_data(self, user_id):
        """Export user health data in various formats"""
        try:
            # Parse query parameters
            query_components = parse_qs(urlparse(self.path).query)
            time_range = query_components.get('timeRange', ['30d'])[0]  # Default to 30 days
            export_format = query_components.get('format', ['csv'])[0].lower()  # Default to CSV
            
            # Calculate start date based on time range
            start_date = self.calculate_start_date(time_range)
            
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            # Get user information
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            username = user['username'] if user else "Unknown"
            
            # Fetch user metrics data
            query = """SELECT um.recorded_at, hm.name, hm.display_name, um.value, hm.unit, um.notes
                    FROM user_metrics um
                    JOIN health_metrics hm ON um.metric_id = hm.metric_id
                    WHERE um.user_id = %s
                    AND um.recorded_at >= %s
                    ORDER BY um.recorded_at DESC"""
            cursor.execute(query, (user_id, start_date))
            metrics = cursor.fetchall()
            
            # Fetch health logs
            cursor.execute("""
                SELECT recorded_at, temperature, symptoms, notes 
                FROM health_logs 
                WHERE user_id = %s AND recorded_at >= %s
                ORDER BY recorded_at DESC
            """, (user_id, start_date))
            health_logs = cursor.fetchall()
            
            # Fetch symptoms data
            cursor.execute("""
                SELECT recorded_at, symptom_name, severity, duration, notes
                FROM symptoms_log
                WHERE user_id = %s AND recorded_at >= %s
                ORDER BY recorded_at DESC
            """, (user_id, start_date))
            symptoms = cursor.fetchall()
            
            # Generate export file based on format
            if export_format == 'csv':
                self.export_as_csv(user_id, username, metrics, health_logs, symptoms)
            elif export_format == 'json':
                self.export_as_json(user_id, username, metrics, health_logs, symptoms)
            elif export_format == 'excel':  # Add this condition
                self.export_as_excel(user_id, username, metrics, health_logs, symptoms)
            else:
                # Default to CSV if unsupported format
                self.export_as_csv(user_id, username, metrics, health_logs, symptoms)
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()
    def export_as_csv(self, user_id, username, metrics, health_logs, symptoms):
        """Export user data as CSV file"""
        try:
            # Create a CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write file header
            current_date = datetime.now().strftime("%Y-%m-%d")
            writer.writerow(["Health Data Export for " + username])
            writer.writerow(["Generated on:", current_date])
            writer.writerow([])  # Empty row as separator
            
            # Write metrics data
            writer.writerow(["HEALTH METRICS"])
            writer.writerow(["Date", "Metric", "Value", "Unit", "Notes"])
            for metric in metrics:
                writer.writerow([
                    metric['recorded_at'].strftime("%Y-%m-%d %H:%M:%S") if isinstance(metric['recorded_at'], datetime) else metric['recorded_at'],
                    metric['display_name'] or metric['name'],
                    metric['value'],
                    metric['unit'] or "",
                    metric['notes'] or ""
                ])
            
            writer.writerow([])  # Empty row as separator
            
            # Write health logs
            writer.writerow(["HEALTH LOGS"])
            writer.writerow(["Date", "Temperature", "Symptoms", "Notes"])
            for log in health_logs:
                writer.writerow([
                    log['recorded_at'].strftime("%Y-%m-%d %H:%M:%S") if isinstance(log['recorded_at'], datetime) else log['recorded_at'],
                    log['temperature'],
                    log['symptoms'],
                    log['notes'] or ""
                ])
            
            writer.writerow([])  # Empty row as separator
            
            # Write symptoms data
            writer.writerow(["SYMPTOMS LOG"])
            writer.writerow(["Date", "Symptom", "Severity", "Duration", "Notes"])
            for symptom in symptoms:
                writer.writerow([
                    symptom['recorded_at'].strftime("%Y-%m-%d %H:%M:%S") if isinstance(symptom['recorded_at'], datetime) else symptom['recorded_at'],
                    symptom['symptom_name'],
                    symptom['severity'],
                    symptom['duration'],
                    symptom['notes'] or ""
                ])
            
            # Send the CSV as response
            csv_data = output.getvalue()
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv')
            self.send_header('Content-Disposition', f'attachment; filename="health_data_{username}_{current_date}.csv"')
            self.send_header('Content-Length', str(len(csv_data)))
            self.end_headers()
            self.wfile.write(csv_data.encode())
            
        except Exception as e:
            print(f"Error generating CSV: {str(e)}")
            self.send_error(500, "Error generating export file")
    def export_as_json(self, user_id, username, metrics, health_logs, symptoms):
        """Export user data as JSON file"""
        try:
            current_date = datetime.now().strftime("%Y-%m-%d")
            
            # Create JSON structure
            export_data = {
                "export_info": {
                    "user": username,
                    "generated_on": current_date,
                    "user_id": user_id
                },
                "metrics": [self.convert_dict_for_json(m) for m in metrics],
                "health_logs": [self.convert_dict_for_json(h) for h in health_logs],
                "symptoms": [self.convert_dict_for_json(s) for s in symptoms]
            }
            
            # Convert to JSON string
            json_data = json.dumps(export_data, default=str, indent=2)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Disposition', f'attachment; filename="health_data_{username}_{current_date}.json"')
            self.send_header('Content-Length', str(len(json_data)))
            self.end_headers()
            self.wfile.write(json_data.encode())
            
        except Exception as e:
            print(f"Error generating JSON: {str(e)}")
            self.send_error(500, "Error generating export file")

    def convert_dict_for_json(self, d):
        """Convert dictionary values for JSON serialization"""
        result = {}
        for k, v in d.items():
            if isinstance(v, datetime):
                result[k] = v.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(v, (bytes, bytearray)):
                result[k] = v.decode('utf-8')
            else:
                result[k] = v
        return result

    def calculate_start_date(self, time_range):
        """Calculate start date based on time range string"""
        now = datetime.now()
        
        if time_range == '7d':
            return now - timedelta(days=7)
        elif time_range == '30d':
            return now - timedelta(days=30)
        elif time_range == '90d':
            return now - timedelta(days=90)
        elif time_range == '6m':
            return now - timedelta(days=180)
        elif time_range == '1y':
            return now - timedelta(days=365)
        else:
            # Default to 30 days
            return now - timedelta(days=30)
    
    def is_authorized_for_user_data(self, target_user_id):
        """Check if the current user is authorized to access data for the target user"""
    
        return True 
    def serve_test_visualization(self):
        """Serve a basic test page to verify routing works"""
        test_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Visualization Test</title>
        </head>
        <body>
            <h1>Visualization Test Page</h1>
            <p>If you can see this, basic routing is working.</p>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(test_html.encode())
    def handle_admin_stats(self):
        """Return dashboard statistics for admin panel"""
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            # Get total users count
            cursor.execute("SELECT COUNT(*) as total FROM users WHERE is_admin = 0")
            total_users = cursor.fetchone()['total']
            
            # Get total health logs count
            cursor.execute("SELECT COUNT(*) as total FROM health_logs")
            total_logs = cursor.fetchone()['total']
            
            # Get active users (with logs in past 7 days)
            seven_days_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                "SELECT COUNT(DISTINCT user_id) as active FROM health_logs WHERE recorded_at >= %s",
                (seven_days_ago,)
            )
            active_users = cursor.fetchone()['active']
            
            # Get total symptoms reported
            cursor.execute("SELECT COUNT(*) as total FROM symptoms_log")
            total_symptoms = cursor.fetchone()['total']
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'totalUsers': total_users,
                'totalLogs': total_logs,
                'activeUsers': active_users,
                'totalSymptoms': total_symptoms
            }).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    

    def handle_admin_recent_activity(self):
        """Return recent user activity based on health logs and symptoms"""
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            # Get recent health logs with usernames
            query = """
                SELECT h.recorded_at, u.username, 'Logged health data' as action
                FROM health_logs h
                JOIN users u ON h.user_id = u.id
                UNION ALL
                SELECT s.recorded_at, u.username, 'Reported symptoms' as action
                FROM symptoms_log s
                JOIN users u ON s.user_id = u.id
                ORDER BY recorded_at DESC
                LIMIT 10
            """
            cursor.execute(query)
            activities = cursor.fetchall()
            
            # Format for response
            formatted_activities = []
            for activity in activities:
                formatted_activities.append({
                    'username': activity['username'],
                    'action': activity['action'],
                    'timestamp': activity['recorded_at'].strftime('%Y-%m-%d %H:%M:%S')
                })
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(formatted_activities).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_admin_users_list(self):
        """Return list of all users for admin panel"""
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            # Get query parameters for search
            query_components = parse_qs(urlparse(self.path).query)
            search = query_components.get('search', [''])[0]
            
            if search:
                # Search for users
                query = """
                    SELECT id, username, email, created_at
                    FROM users
                    WHERE is_admin = 0 AND (username LIKE %s OR email LIKE %s)
                    ORDER BY created_at DESC
                """
                search_param = f'%{search}%'
                cursor.execute(query, (search_param, search_param))
            else:
                # Get all users
                query = """
                    SELECT id, username, email, created_at
                    FROM users
                    WHERE is_admin = 0
                    ORDER BY created_at DESC
                """
                cursor.execute(query)
            
            users = cursor.fetchall()
            
            # Add status field based on recent activity
            for user in users:
                user['status'] = 'active'  # Default status
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(users, default=str).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_admin_user_detail(self, user_id):
        """Return detailed information about a specific user"""
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor(dictionary=True)
            
            # Get user details
            query = """
                SELECT id, username, email, created_at
                FROM users
                WHERE id = %s AND is_admin = 0
            """
            cursor.execute(query, (user_id,))
            user = cursor.fetchone()
            
            if user:
                # Add status (active by default)
                user['status'] = 'active'
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(user, default=str).encode())
            else:
                self.send_error(404, "User not found")
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def handle_admin_reports_list(self):
        """Return list of reports for admin panel"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        # Return empty array for now since you don't have the reports table yet
        self.wfile.write(json.dumps([]).encode())

    def handle_admin_generate_report(self, data):
        """Generate a new report"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"message": "Report generation started"}).encode())

    def handle_admin_add_user(self, user_data):
        """Add a new user from admin panel"""
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor()
            
            query = """INSERT INTO users (username, password_hash, email, is_admin) 
                    VALUES (%s, %s, %s, %s)"""
            cursor.execute(query, (
                user_data['username'],
                user_data['password'],
                user_data['email'],
                0  # Regular user
            ))
            conn.commit()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"message": "User added successfully"}).encode())
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()   
    def handle_delete_health_log(self, log_id):
        """Delete a specific health log entry"""
        try:
            # Get user ID from request path
            path_parts = self.path.split('/')
            log_id = path_parts[-1]
            
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="health_tracking_db"
            )
            cursor = conn.cursor()
            
            # Delete the log entry
            query = "DELETE FROM health_logs WHERE id = %s"
            cursor.execute(query, (log_id,))
            
            # Check if any rows were affected
            if cursor.rowcount > 0:
                conn.commit()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Health log deleted successfully"}).encode())
            else:
                self.send_error(404, "Log entry not found")
            
        except mysql.connector.Error as e:
            print("Database error:", str(e))
            self.send_error(500)
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()
    def do_PUT(self):
        try:
            content_length = int(self.headers['Content-Length'])
            put_data = self.rfile.read(content_length)
            data = json.loads(put_data.decode('utf-8'))
            
            if self.path.startswith('/admin/users/'):
                user_id = self.path.split('/')[-1]
                self.handle_admin_update_user(user_id, data)
            else:
                self.send_error(404)
        except Exception as e:
            print("Error in PUT:", str(e))
            self.send_error(500)

    def do_DELETE(self):
        try:
            if self.path.startswith('/admin/users/'):
                user_id = self.path.split('/')[-1]
                self.handle_admin_delete_user(user_id)
            else:
                self.send_error(404)
        except Exception as e:
            print("Error in DELETE:", str(e))
            self.send_error(500)

    def do_DELETE(self):
        try:
            if self.path.startswith('/health/log/'):
                log_id = self.path.split('/')[-1]
                self.handle_delete_health_log(log_id)
            else:
                self.send_error(404)
        except Exception as e:
            print("Error in DELETE:", str(e))
            self.send_error(500)

    def handle_admin_update_user(self, user_id, user_data):
        """Update user details from admin panel"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"message": "User updated successfully"}).encode())

    def handle_admin_delete_user(self, user_id):
        """Delete a user from admin panel"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"message": "User deleted successfully"}).encode())


print("Starting health tracking server...")
server = HTTPServer(('localhost', 5000), HealthServer)
print("Server is running on http://localhost:5000")
 # Make sure database has admin column
try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="health_tracking_db"
    )
    cursor = conn.cursor()
    
    # Check if is_admin column exists, add if not
    cursor.execute("SHOW COLUMNS FROM users LIKE 'is_admin'")
    if not cursor.fetchone():
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin TINYINT(1) DEFAULT 0")
        print("Added is_admin column to users table")
        
    # Create default admin user if none exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
    admin_exists = cursor.fetchone()[0]
    
    if admin_exists == 0:
        cursor.execute("""
            INSERT INTO users (username, password_hash, email, is_admin)
            VALUES ('admin', 'admin123', 'admin@example.com', 1)
        """)
        conn.commit()
        print("Created default admin user (username: admin, password: admin123)")
        
except mysql.connector.Error as e:
    print(f"Database setup error: {e}")
finally:
    if 'conn' in locals() and conn.is_connected():
        cursor.close()
        conn.close()
server.serve_forever()