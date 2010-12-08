<?php
/*
This is a web interface that allows developers to clobber buildbot
builds on a per-slave/per-builder basis.

This script simply updates a database that Buildbot reads from at the start of
every build.
http://hg.mozilla.org/build/buildbotcustom/file/default/process/factory.py
*/

$CLOBBERER_DB = 'db/clobberer.db';

$PLATFORMS = array('linux', 'linux64', 'macosx', 'macosx64', 'win32', 'wince');

$RELEASE_BUILDERS = array(
  'tag',
  'source',
  'updates',
  'major_update',
  'final_verification',
);
$RELEASE_PREFIX = 'release-';

foreach ($PLATFORMS as $platform){
  $RELEASE_BUILDERS[] = "${platform}_build";
  $RELEASE_BUILDERS[] = "${platform}_repack";
  $RELEASE_BUILDERS[] = "${platform}_l10n_verification";
  $RELEASE_BUILDERS[] = "${platform}_update_verify";
  $RELEASE_BUILDERS[] = "${platform}_major_update_verify";
  $RELEASE_BUILDERS[] = "${platform}_test mochitests";
  $RELEASE_BUILDERS[] = "${platform}_test mochitest-other";
  $RELEASE_BUILDERS[] = "${platform}_test reftest";
  $RELEASE_BUILDERS[] = "${platform}_test crashtest";
  $RELEASE_BUILDERS[] = "${platform}_test xpcshell'";
}

// TODO: Figure out if we can use LDAP to do this
$SPECIAL_PEOPLE = array(
  'armenzg@mozilla.com',
  'asasaki@mozilla.com',
  'bhearsum@mozilla.com',
  'catlee@mozilla.com',
  'coop@mozilla.com',
  'jford@mozilla.com',
  'joduinn@mozilla.com',
  'lsblakk@mozilla.com',
  'mtaylor@mozilla.com',
  'nthomas@mozilla.com',
  'raliiev@mozilla.com',
);

$dbh = new PDO("sqlite:$CLOBBERER_DB");
if (!$dbh) {
  header('HTTP/1.0 500 Internal Server Error');
  print("<h1>Error: couldn't connect</h1>");
  print($error);
  exit(0);
}

$q = $dbh->query('SELECT count(*) FROM sqlite_master WHERE NAME="clobber_times"');
$exists = $q->fetch(PDO::FETCH_NUM);
if (!$exists or !$exists[0]) {
  $res = $dbh->exec('CREATE TABLE builds ('
                   .'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                   .'master VARCHAR(100),'
                   .'branch VARCHAR(50),'
                   .'buildername VARCHAR(100),'
                   .'builddir VARCHAR(100),'
                   .'slave VARCHAR(30),'
                   .'last_build_time INTEGER)');
  if ($res === FALSE) {
    die(print_r($dbh->errorInfo(), TRUE));
  }

  $res = $dbh->exec('CREATE TABLE clobber_times ('
                   .'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                   .'master VARCHAR(100),'
                   .'branch VARCHAR(50),'
                   .'builddir VARCHAR(100),'
                   .'slave VARCHAR(30),'
                   .'lastclobber INTEGER,'
                   .'who VARCHAR(50))');
  if ($res === FALSE) {
    die(print_r($dbh->errorInfo(), TRUE));
  }
  chmod($CLOBBERER_DB, 0660);
}

function isSpecial($user)
{
  // TODO: Figure out if we can use LDAP to get the group of $user
  global $SPECIAL_PEOPLE;
  return in_array($user, $SPECIAL_PEOPLE);
}

function canSee($builddir, $user)
{
  global $RELEASE_BUILDERS;
  global $RELEASE_PREFIX;
  if (!in_array($builddir, $RELEASE_BUILDERS) && strpos($builddir, $RELEASE_PREFIX)!=0) {
    return true;
  }

  return isSpecial($user);
}

function b64_encode($s)
{
  return rtrim(base64_encode($s), "=");
}

function e($str)
{
  global $dbh;
  return $dbh->quote($str);
}

function getBuilders($slave)
{
  global $dbh;
  $slave = e($slave);
  $retval = array();
  $builders = $dbh->query("SELECT DISTINCT builddir from builds where slave=$slave");
  while ($r = $builders->fetch(PDO::FETCH_ASSOC)) {
    // Find the most recent build for this builder
    $builddir = e($r['builddir']);
    $build = $dbh->query("SELECT buildername, builddir, branch FROM builds WHERE builddir = $builddir ORDER by last_build_time DESC LIMIT 1");
    $r = $build->fetch(PDO::FETCH_ASSOC);
    if ($r) {
      $retval[] = $r;
    }
  }
  return $retval;
}

function getMasters()
{
  global $dbh;
  $retval = array();
  $masters = $dbh->query("SELECT DISTINCT master from builds");
  while ($r = $masters->fetch(PDO::FETCH_ASSOC)) {
    $retval[] = $r['master'];
  }
  return $retval;
}

function updateBuildTime($master, $branch, $buildername, $builddir, $slave)
{
  global $dbh;
  $master = e($master);
  $branch = e($branch);
  $buildername = e($buildername);
  $builddir = e($builddir);
  $slave = e($slave);
  $now = time();

  $rows = $dbh->exec("UPDATE builds SET last_build_time = $now WHERE master=$master AND "
      ."branch=$branch AND buildername=$buildername AND slave=$slave");
  if ($rows == 0) {
      $dbh->exec("INSERT INTO builds "
          ."(master, branch, buildername, builddir, slave, last_build_time) VALUES "
          ."($master, $branch, $buildername, $builddir, $slave, $now)");
      return true;
  }
  return false;
}

function getClobberTime($master, $branch, $builddir, $slave)
{
  global $dbh;
  $master = e($master);
  $branch = e($branch);
  $builddir = e($builddir);
  $slave = e($slave);
  $q = "SELECT id, who, lastclobber FROM clobber_times WHERE "
      ."builddir = $builddir AND (branch IS NULL OR branch = $branch) AND "
      ."(master IS NULL OR master = $master) AND (slave IS NULL OR slave = $slave) "
      ."ORDER BY lastclobber DESC LIMIT 1";
  $s = $dbh->query($q);
  $r = $s->fetch(PDO::FETCH_ASSOC);
  if (!$r) {
    return null;
  }
  else
  {
    return $r;
  }
}

//
// Handle form submission
//
if ($_POST['form_submitted']) {
  $clobbers = array();
  $slaves = array();
  $user = $_SERVER['REMOTE_USER'];
  $e_user = e($user);
  $now = time();
  foreach ($_POST as $k => $v) {
    if ($k == "master") {
      if (isSpecial($user)) {
        $branch = $_POST['branch'];
        if ($branch != '') {
          $branch = e($branch);
        } else {
          $branch = 'NULL';
        }

        if ($v != '') {
          $master = e($v);
        } else {
          $master = 'NULL';
        }

        $builddir = $_POST['builddir'];
        if ($builddir != '') {
            $builders = array($builddir);
            // check for release-${branch}- version of this builddir
            $releasedir = e("$RELEASE_PREFIX%$builddir%");
            $q = "SELECT DISTINCT builddir FROM builds "
                ."WHERE "
                ."builddir LIKE $releasedir"
                . (($branch != 'NULL') ? " AND branch == $branch" : "")
                . (($master != 'NULL') ? " AND master == $master" : "");
            $s = $dbh->query($q);
            error_log("Executing query: $q");
            while ($s && $r = $s->fetch(PDO::FETCH_ASSOC)) {
                $builders[] = $r['builddir'];
            }
        } else {
            $builders = $RELEASE_BUILDERS;
            // grab all release-* versions of the release-builders
            $q = "SELECT DISTINCT builddir FROM builds "
                ."WHERE "
                ."builddir like '". $RELEASE_PREFIX . "%'"
                . (($branch != 'NULL') ? " AND branch == $branch" : "")
                . (($master != 'NULL') ? " AND master == $master" : "");
            $s = $dbh->query($q);
            error_log("Executing query $q");
            while ($s && $r = $s->fetch(PDO::FETCH_ASSOC)) {
              $builders[] = $r['builddir'];
            }
        }

        foreach ($builders as $builddir) {
          $builddir = e($builddir);
          error_log("inserting master: $master, branch: $branch, builddir: $builddir into clobberer.db");
          $q = "INSERT INTO clobber_times "
              ."(master, branch, builddir, slave, who, lastclobber) VALUES "
              ."($master, $branch, $builddir, NULL, $e_user, $now)";
          $dbh->exec($q) or die(print_r($dbh->errorInfo(), TRUE));
        }
      }
      continue;
    }
    $t = explode('-', $k, 2);
    // We only care about slave-<$row_id>
    // This corresponds to a row that specifies which branch/builder/slave to clobber
    if ($t[0] == 'slave') {
      $row_id = e($t[1]);
      $s = $dbh->query("SELECT * from builds where id = $row_id");
      $r = $s->fetch(PDO::FETCH_ASSOC);
      if ($r)
      {
        $builddir = e($r['builddir']);
        $branch = e($r['branch']);
        $slave = e($r['slave']);
        if (canSee($builddir, $user)) {
            $dbh->exec("INSERT INTO clobber_times "
                ."(master, branch, builddir, slave, who, lastclobber) VALUES "
                ."(NULL, $branch, $builddir, $slave, $e_user, $now)") or die(print_r($$dbh->errorInfo(), TRUE));
        }
      }
    }
  }
  // Redirect the user to the main page
  // This prevents accidentally resubmitting the form if the user reloads the 
  // page
  header("Location: " . $_SERVER['REQUEST_URI']);
}

$buildername = urldecode($_GET['buildername']);
$builddir = urldecode($_GET['builddir']);
$slave = urldecode($_GET['slave']);
$branch = urldecode($_GET['branch']);
$master = urldecode($_GET['master']);
// Show the administration page if no clobber time is being queried
if (!$buildername) {
?>
<html>
<head>
<title>Mozilla Buildbot Clobberer</title>
<link rel="stylesheet" href="clobberer.css" type="text/css" />
<script src="jquery.min.js" language="javascript"></script>
<script language="javascript">
function toggleall(node, klass)
{
  if (klass) {
    $("." + klass).attr("checked", node.checked);
  }
  var node_classes = $(node).attr("class").split(" ");
  if (!node.checked) {
    // If we just unchecked a node, then uncheck the parents too
    for (var i = 0; i < node_classes.length; ++i) {
      if (node_classes[i]) {
        $("#" + node_classes[i]).attr("checked", false);
      }
    }
  } else {
    // If we just checked a node, then possibly check the parents if all
    // children are checked
    var done = false;
    while (!done) {
      done = true;
      for (var i = 0; i < node_classes.length; ++i) {
        if (node_classes[i]) {
          // If none of this class is unchecked, then we can check the parent
          if ($("." + node_classes[i] + ":not(:checked)").length == 0) {
            var p = $("#" + node_classes[i]);
            if (p && !p.attr("checked")) {
              p.attr("checked", true);
              // Loop through again if we just set our parent to checked
              done = false;
            }
          }
        }
      }
    }
  }
}
</script>
</head>
<body>
<p>This page is used for clobbering buildbot-based builds.</p>
<p>Please read
<a href="https://wiki.mozilla.org/Build:ClobberingATinderbox">Build:ClobberingATinderbox</a>
and/or <a href="https://wiki.mozilla.org/Clobbering_the_Tree">Clobbering the Tree</a>
for more information about what this page is for, and how to use it.</p>
<?php
  if (isSpecial($_SERVER['REMOTE_USER'])) {
?>
<h1>Release Clobbers</h1>
<form method="POST">
<input type="hidden" name="form_submitted" value="true">
Clobber all release builders on <select name="master">
<option value="">Any master</option>
<?php
  $masters = getMasters();
  foreach ($masters as $master) {
    $e_master = htmlspecialchars($master);
    print "<option value=\"$e_master\">$master</option>\n";
  }
?>
</select>
<select name="branch">
<option value="">Any release</option>
<?php
  $builders = "";
  $first = true;
  foreach ($RELEASE_BUILDERS as $b) {
    if (!$first) {
      $builders .= ",";
    }
    $first = false;
    $builders .= e($b);
  }
  $releases = $dbh->query("SELECT DISTINCT branch FROM builds WHERE builddir IN ($builders)");
  while ($release = $releases->fetch(PDO::FETCH_ASSOC)) {
    $release = $release['branch'];
    $e_release = htmlspecialchars($release);
    print "<option value=\"$e_release\">$release</option>\n";
  }
?>
</select>
<select name="builddir">
<option value="">Any builder</option>
<?php
  $builders = "";
  $first = true;
  foreach ($RELEASE_BUILDERS as $b) {
    $e_b = htmlspecialchars($b);
    print "<option value=\"$e_b\">$b</option>\n";
  }
?>
</select>

<input type="submit" value="Wipe them out!">
</form>

<h1>Regular Clobbers</h1>

<?php } ?>

<form method="POST">
<table border="1" cellspacing="0" cellpadding="1">
 <thead>
  <tr><td>Branch</td><td>Builder Name</td><td>Slaves</td><td>Last clobbered</td></tr>
 </thead>
 <tbody>
<?php
  $allbuilders = $dbh->query('SELECT DISTINCT id, branch, builddir, buildername, slave FROM builds ORDER BY branch ASC, buildername ASC');
  if ($allbuilders) {
    $last_branch = null;
    $last_builder = null;
    // First pass: count the number of rows for each branch / buildername so we can 
    // set the 'rowspan' attribute
    $rows_per_branch = array();
    $rows_per_builder = array();
    $rows = array();
    while ($r = $allbuilders->fetch(PDO::FETCH_ASSOC)) {
      if (!canSee($r['builddir'], $_SERVER['REMOTE_USER'])) {
        continue;
      }
      $rows[] = $r;
      $buildername = $r['buildername'];
      $branch = $r['branch'];
      if (!array_key_exists($branch, $rows_per_builder)) {
        $rows_per_builder[$branch] = array();
      }
      if (!array_key_exists($buildername, $rows_per_builder[$branch])) {
        $rows_per_builder[$branch][$buildername] = 1;
      } else {
        $rows_per_builder[$branch][$buildername] += 1;
      }
      if (!array_key_exists($branch, $rows_per_branch)) {
        $rows_per_branch[$branch] = 1;
      } else {
        $rows_per_branch[$branch] += 1;
      }
    }
    // Sort the results
    function sort_func($r1, $r2) {
      $c1 = strnatcmp($r1['branch'], $r2['branch']);
      if ($c1 != 0) {
        return $c1;
      }
      $c2 = strnatcmp($r1['buildername'], $r2['buildername']);
      if ($c2 != 0) {
        return $c2;
      }
      return strnatcmp($r1['slave'], $r2['slave']);
    }
    usort($rows, sort_func);
    // Second pass we output the HTML
    foreach ($rows as $r) {
      print "<tr>";
      if ($last_branch != $r['branch']) {
        $branch_id = b64_encode($r['branch']);
        $rowspan = $rows_per_branch[$r['branch']];
        print "<td rowspan=\"$rowspan\">";
        print "<input type=\"checkbox\" id=\"$branch_id\" onchange=\"toggleall(this, &quot;$branch_id&quot;)\" />";
        print htmlspecialchars($r['branch']) . "</td>\n";
      }
      if ($last_builder != $r['buildername']) {
        $rowspan = $rows_per_builder[$r['branch']][$r['buildername']];
        $builder_id = b64_encode($r['buildername']);
        $classes = b64_encode($r['branch']);
        print "<td rowspan=\"$rowspan\"><input type=\"checkbox\" id=\"$builder_id\" class=\"$classes\" onchange=\"toggleall(this, &quot;$builder_id&quot;)\" />";
        print htmlspecialchars($r['buildername']) . "</td>\n";
      }
      $classes = b64_encode($r['buildername']) . " " . b64_encode($r['branch']);
      $name = "slave-" . $r['id'];
      print "<td><input type=\"checkbox\" name=\"$name\" class=\"$classes\" onchange=\"toggleall(this)\" />";
      print htmlspecialchars($r['slave']) . "</td>\n";
      $lastclobber = getClobberTime(null, $r['branch'], $r['builddir'], $r['slave']);
      if ($lastclobber) {
        print "<td>" . strftime("%Y-%m-%d %H:%M:%S %Z", $lastclobber['lastclobber']) . " by " . htmlspecialchars($lastclobber['who']) . "</td>\n";
      } else {
        print "<td></td>\n";
      }
      print "</tr>\n";
      $last_branch = $r['branch'];
      $last_builder = $r['buildername'];
    }
  } else {
    print "<tr><td colspan=\"9\">No data</td></tr>\n";
  }
?>
 </tbody>
</table>
<input type="hidden" name="form_submitted" value="true">
<input type="submit" value="Clobber now">
</form>
</body>
</html>
<?php
  exit(0);
}

// Handle requests from slaves asking about their last clobber date

// First, find the list of builders for this slave
$slave_builders = getBuilders($slave);

// Make sure that the current branch/builder is in that list
$found = false;
foreach ($slave_builders as $sb) {
    if ($sb['builddir'] == $builddir && $sb['branch'] == $branch) {
        $found = true;
        break;
    }
}
if (!$found) {
    $slave_builders[] = array('builddir' => $builddir, 'branch' => $branch);
}

// And check the clobber time for each buildername
$clobber_times = array();
foreach ($slave_builders as $sb) {
  $r = getClobberTime($master, $sb['branch'], $sb['builddir'], $slave);
  if ($r) {
    if (!array_key_exists($sb['builddir'], $clobber_times)) {
      $clobber_times[$sb['builddir']] = array('lastclobber'=>$r['lastclobber'], 'who'=>$r['who']);
    } else {
      $t = $clobber_times[$sb['builddir']]['lastclobber'];
      if ($r['lastclobber'] > $t) {
        $clobber_times[$sb['builddir']] = array('lastclobber'=>$r['lastclobber'], 'who'=>$r['who']);
      }
    }
  }
}

// Tell the slave what to clobber
foreach ($clobber_times as $b => $r) {
  $lastclobber = $r['lastclobber'];
  $who = $r['who'];
  print "$b:$lastclobber:$who\n";
}

// Finally, update our table of when builds are happening
$new = updateBuildTime($master, $branch, $buildername, $builddir, $slave);

?>
