


#define for_each_dpeer(dpg, dp) for( ... ; ... ; ... )




void func(dpg_t *dpg)
{
	dpeer_t *dp;
	for_each_dpeer(dpg, dp) {

		/* do something with dp */
	}

}
