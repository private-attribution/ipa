// DP budgets

pub struct Epoch {
    epoch_id: u32,
    epoch_budget: u32,
}

pub struct SiteBudget {
    pub domain: String,
    //pub public_key: ??,

    // suppose we store budget for 5 epochs
    // TODO: probably better to store as an array
    pub current_week: Epoch,
    pub last_week: Epoch,
    pub two_weeks_ago: Epoch,
    pub three_weeks_ago: Epoch,
    pub four_weeks_ago: Epoch,
}

/// we'll need some sort of store for the budgets of multiple sites
// let mut budget_database : Vec<SiteBudget> = Vec::new();


/// We'll need a function that gets the current epoch
pub fn get_current_epoch() {
    // translate current time into the epoch id
}


impl SiteBudget {
    pub fn register_site_for_budget(){

    }


    /// using that current epoch we could add available budget to a site for
    /// new epochs and expire old epochs
    pub fn update_budget_for_new_epoch(){

    }
}

/// DP budget verifications for a query
pub fn dp_verifications_for_query() {

}

