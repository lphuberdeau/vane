
class VaneOutput
  def initialize(verbose)
    @verbose = verbose
  end

  def start()
    banner() # called after $log set
  end

  def version()
    puts "Current version: #{VANE_VERSION}"
  end

  def follow_redirection(redirection)
    puts "Following redirection #{redirection}"
  end

  def set_url(url)
    puts "#{info('[+]')} URL: #{url}"
  end

  def set_start_time(start_time)
    puts "#{info('[+]')} Started: #{start_time.asctime}"
    puts
  end

  def wordpress_hosted_warning()
    puts "#{critical('[!]')} We do not support scanning *.wordpress.com hosted blogs"
  end

  def set_robots_url(url)
    puts "#{info('[+]')} robots.txt available under: '#{url}'"
  end

  def add_robots_entry(dir)
    puts "#{info('[+]')} Interesting entry from robots.txt: #{dir}"
  end

  def set_readme_url(url)
    puts "#{warning('[!]')} The WordPress '#{url}' file exists exposing a version number"
  end

  def set_full_path_disclosure_url(url)
    puts "#{warning('[!]')} Full Path Disclosure (FPD) in: '#{url}'"
  end

  def set_debug_log_url(url)
    puts "#{critical('[!]')} Debug log file found: #{url}"
  end

  def add_backup_file(url)
    puts "#{critical('[!]')} A wp-config.php backup file has been found in: '#{url}'"
  end

  def set_searchreplacedb2_url(url)
    puts "#{critical('[!]')} searchreplacedb2.php has been found in: '#{url}'"
  end

  def add_interesting_header(key, value)
    output = "#{info('[+]')} Interesting header: "
    puts output + "#{key}: #{value}"
  end

  def multisite_warning()
    puts "#{info('[+]')} This site seems to be a multisite (http://codex.wordpress.org/Glossary#Multisite)"
  end

  def must_use_plugins_warning()
    puts "#{info('[+]')} This site has 'Must Use Plugins' (http://codex.wordpress.org/Must_Use_Plugins)"
  end

  def set_registration_url(url)
    puts "#{warning('[+]')} Registration is enabled: #{url}"
  end

  def set_xmlrpc_url(url)
    puts "#{info('[+]')} XML-RPC Interface available under: #{url}"
  end

  def set_upload_dir_url(url)
    puts "#{warning('[!]')} Upload directory has directory listing enabled: #{url}"
  end

  def set_version(wp_version)
    wp_version.output(@verbose)
  end

  def version_undetected_warning()
      puts
      puts "#{notice('[i]')} WordPress version can not be detected"
  end

  def set_active_theme(wp_theme)
      puts
      # Theme version is handled in #to_s
      puts "#{info('[+]')} WordPress theme in use: #{wp_theme}"
      wp_theme.output(@verbose)
  end

  def add_parent_theme(wp_theme)
    puts
    puts "#{info('[+]')} Detected parent theme: #{parent}"
    parent.output(@verbose)
  end

  def begin_passive_detection()
    puts
    puts "#{info('[+]')} Enumerating plugins from passive detection ..."
  end

  def set_passive_plugin_count(size)
    if size > 0
      puts " | #{size} plugins found:"
    else
      puts "#{info('[+]')} No plugins found"
    end
  end

  def set_passive_plugins(wp_plugins)
    wp_plugins.output(@verbose)
  end

  def begin_enumerate_plugins(vulnerable_only)
    puts
    puts "#{info('[+]')} Enumerating installed plugins #{'(only vulnerable ones)' if vulnerable_only} ..."
    puts
  end

  def set_aggressive_plugin_count(size)
    puts
    if size > 0
      puts "#{info('[+]')} We found #{wp_plugins.size} plugins:"
    else
      puts "#{info('[+]')} No plugins found"
    end
  end

  def set_aggressive_plugins(wp_plugins)
    wp_plugins.output(@verbose)
  end
end
