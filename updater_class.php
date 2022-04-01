<?php

class updater{


    //Public functions
    static public function do_file_update($filepath,$update_path,$no_cache = true){

        
        //check vars
        if(is_string($filepath)<>true)return("Not a valid file path.");
        if(is_string($update_path)<>true)return("Not a valid update path.");


        //get values
        $response_result = self::download_file_text($update_path,$no_cache);
        $contents = self::read_file($filepath);
        
        
        //compare values
        if($contents<>$response_result){
            $a = file_put_contents($filepath, $response_result);
            if($contents<>$response_result){
                return("Error: Update needed! Please update first.");
            }else{
                return true;
            }
        }else{
            return true;
        }


}

static public function check_new_update($filepath,$update_path,$no_cache = true){

        
        //check vars
        if(is_string($filepath)<>true)return("Not a valid file path.");
        if(is_string($update_path)<>true)return("Not a valid update path.");


        //get values
        $response_result = self::download_file_text($update_path,$no_cache);
        $contents = self::read_file($filepath);
    
    
    if($contents<>$response_result){
        //new update available
        return true;
    }else{
        //no update available
        return false;
    }


}

static public function html_output($filepath,$update_path,$no_cache = true){

 
    if(self::check_new_update($filepath,$update_path,$no_cache)==true){
        //new update available
        return "New update available for: " . $filepath . ".";
    }else{
        //no update available
        return "No new update available.";
    }

}


static public function hash_my_file($filepath, $hash_type = "sha256"){
            //check vars
            if(is_string($filepath)<>true)return("Not a valid file path.");
            if(is_string($hash_type)<>true)return("Not a valid hash type.");
            //get values
            $contents = self::read_file($filepath);
            return hash($hash_type,$contents);
}


static public function hash_update_file($update_path,$hash_type = "sha256",$no_cache = true){
            //check vars
            if(is_string($update_path)<>true)return("Not a valid update path.");
            if(is_string($hash_type)<>true)return("Not a valid hash type.");
            //get values
            $response_result = self::download_file_text($update_path,$no_cache);
            return hash($hash_type,$response_result);

}


//Private functions
function __construct()
{
    //prevent creating object of updater
}

static private function download_file_text($update_path,$no_cache = true){

     //check vars
     if(is_string($update_path)<>true)return("Not a valid update path.");
     
     if($no_cache==true){
             $update_path=$update_path . "?" . mt_rand();   
     }
    
     $response_result = file_get_contents($update_path);

     //check response
     if(is_string($response_result)<>true)return("Not a valid response result.");
     
     //precheck result
     if($response_result ==false){
        return("Error: was not able to check update.(Update path: " . $update_path . ")<br>");
     }
     return $response_result;
}


static private function read_file($filepath){

        //check vars
        if(is_string($filepath)<>true)return("Not a valid file path.");

        $contents="";
        $fs = fopen( $filepath, "a+" );
        while (!feof($fs)) {
            $contents .= fgets($fs, 1024);
        }
        fclose($fs);



        return $contents;
}




}


?>
