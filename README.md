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
