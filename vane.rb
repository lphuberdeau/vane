#!/usr/bin/env ruby
# encoding: UTF-8

$: << '.'
require File.dirname(__FILE__) + '/lib/vane/vane_helper'

def main
  # delete old logfile, check if it is a symlink first.
  File.delete(LOG_FILE) if File.exist?(LOG_FILE) and !File.symlink?(LOG_FILE)

  begin
    vane_options = VaneOptions.load_from_arguments
    vane_output = VaneOutput.new(vane_options.verbose)

    $log = vane_options.log

    vane_output.start

    unless vane_options.has_options?
      # first parameter only url?
      if ARGV.length == 1
        vane_options.url = ARGV[0]
      else
        usage()
        raise('No argument supplied')
      end
    end

    # Define a global variable
    $COLORSWITCH = vane_options.no_color

    if vane_options.help
      help()
      usage()
      exit(0)
    end

    if vane_options.version
      vane_output.version
      exit(0)
    end

    # Initialize the browser to allow the db update
    # to be done over a proxy if set
    Browser.instance(
      vane_options.to_h.merge(max_threads: vane_options.threads)
    )

    # Figure out something for that.
    #if vane_options.update || missing_db_file?
    #  puts "#{notice('[i]')} Updating the Database ..."
    #  DbUpdater.new(DATA_DIR).update(vane_options.verbose)
    #  puts "#{notice('[i]')} Update completed."
    #  # Exit program if only option --update is used
    #  exit(0) unless vane_options.url
    #end

    unless vane_options.url
      raise 'The URL is mandatory, please supply it with --url or -u'
    end

    wp_target = WpTarget.new(vane_options.url, vane_options.to_h)

    # Remote website up?
    unless wp_target.online?
      raise "The WordPress URL supplied '#{wp_target.uri}' seems to be down."
    end

    if vane_options.proxy
      proxy_response = Browser.get(wp_target.url)

      unless WpTarget::valid_response_codes.include?(proxy_response.code)
        raise "Proxy Error :\r\nResponse Code: #{proxy_response.code}\r\nResponse Headers: #{proxy_response.headers}"
      end
    end

    # Remote website has a redirection?
    if (redirection = wp_target.redirection)
      if vane_options.follow_redirection
        vane_output.follow_redirection(redirection)
      else
        puts "#{notice('[i]')} The remote host tried to redirect to: #{redirection}"
        print '[?] Do you want follow the redirection ? [Y]es [N]o [A]bort, default: [N]'
      end
      if vane_options.follow_redirection || !vane_options.batch
        if vane_options.follow_redirection || (input = Readline.readline) =~ /^y/i
          vane_options.url = redirection
          wp_target = WpTarget.new(redirection, vane_options.to_h)
        else
          if input =~ /^a/i
            puts 'Scan aborted'
            exit(0)
          end
        end
      end
    end

    if wp_target.has_basic_auth? && vane_options.basic_auth.nil?
      raise 'Basic authentication is required, please provide it with --basic-auth <login:password>'
    end

    # test for valid credentials
    unless vane_options.basic_auth.nil?
      res = Browser.get_and_follow_location(wp_target.url)
      raise 'Invalid credentials supplied' if res && res.code == 401
    end

    # Remote website is wordpress?
    unless vane_options.force
      unless wp_target.wordpress?
        raise "#{critical('[!]')} The remote website is up, but does not seem to be running WordPress."
      end
    end

    unless wp_target.wp_content_dir
      raise 'The wp_content_dir has not been found, please supply it with --wp-content-dir'
    end

    unless wp_target.wp_plugins_dir_exists?
      puts "The plugins directory '#{wp_target.wp_plugins_dir}' does not exist."
      puts 'You can specify one per command line option (don\'t forget to include the wp-content directory if needed)'
      puts '[?] Continue? [Y]es [N]o, default: [N]'
      if vane_options.batch || Readline.readline !~ /^y/i
        exit(0)
      end
    end

    # Output runtime data
    start_time   = Time.now
    start_memory = get_memory_usage
    vane_output.set_url(wp_target.url)
    vane_output.set_start_time(start_time)

    if wp_target.wordpress_hosted?
      vane_output.wordpress_hosted_warning
    end

    if wp_target.has_robots?
      vane_output.set_robots_url(wp_target.robots_url)

      wp_target.parse_robots_txt.each do |dir|
        vane_output.add_robots_entry(dir)
      end
    end

    if wp_target.has_readme?
      vane_output.set_readme_url(wp_target.readme_url)
    end

    if wp_target.has_full_path_disclosure?
      vane_output.set_full_path_disclosure_url(wp_target.full_path_disclosure_url)
    end

    if wp_target.has_debug_log?
      vane_output.set_debug_log_url(wp_target.debug_log_url)
    end

    wp_target.config_backup.each do |file_url|
      vane_output.add_backup_file(file_url)
    end

    if wp_target.search_replace_db_2_exists?
      vane_output.set_searchreplacedb2_url(wp_target.search_replace_db_2_url)
    end

    wp_target.interesting_headers.each do |header|

      if header[1].class == Array
        header[1].each do |value|
          vane_output.add_interesting_header(header[0], value)
        end
      else
        vane_output.add_interesting_header(header[0], header[1])
      end
    end

    if wp_target.multisite?
      vane_output.multisite_warning
    end

    if wp_target.has_must_use_plugins?
      vane_output.must_use_plugins_warning
    end

    if wp_target.registration_enabled?
      vane_output.set_registration_url(wp_target.registration_url)
    end

    if wp_target.has_xml_rpc?
      vane_output.set_xmlrpc_url(wp_target.xml_rpc_url)
    end

    if wp_target.upload_directory_listing_enabled?
      vane_output.set_upload_dir_url(wp_target.upload_dir_url)
    end

    enum_options = {
      show_progression: true,
      exclude_content: vane_options.exclude_content_based
    }

    if wp_version = wp_target.version(WP_VERSIONS_FILE)
      vane_output.set_version(wp_version)
    else
      vane_output.version_undetected_warning
    end

    if wp_theme = wp_target.theme
      vane_output.set_active_theme(wp_theme)

      # Check for parent Themes
      parent_theme_count = 0
      while wp_theme.is_child_theme? && parent_theme_count <= wp_theme.parent_theme_limit
        parent_theme_count += 1

        parent = wp_theme.get_parent_theme
        vane_output.add_parent_theme(parent)
        wp_theme = parent
      end

    end

    if vane_options.enumerate_plugins == nil and vane_options.enumerate_only_vulnerable_plugins == nil
      vane_output.begin_passive_detection

      wp_plugins = WpPlugins.passive_detection(wp_target)
      vane_output.set_passive_plugin_count(wp_plugins.size)

      if !wp_plugins.empty?
        vane_output.set_passive_plugins(wp_plugins)
      end
    end

    # Enumerate the installed plugins
    if vane_options.enumerate_plugins or vane_options.enumerate_only_vulnerable_plugins or vane_options.enumerate_all_plugins
      vane_output.begin_enumerate_plugins(vane_options.enumerate_only_vulnerable_plugins)

      wp_plugins = WpPlugins.aggressive_detection(wp_target,
        enum_options.merge(
          file: vane_options.enumerate_all_plugins ? PLUGINS_FULL_FILE : PLUGINS_FILE,
          only_vulnerable: vane_options.enumerate_only_vulnerable_plugins || false
        )
      )
      vane_output.set_aggressive_plugin_count(wp_plugins.size)
      if !wp_plugins.empty?
        vane_putput.set_aggressive_plugins(wp_plugins)
      end
    end

    # Enumerate installed themes
    if vane_options.enumerate_themes or vane_options.enumerate_only_vulnerable_themes or vane_options.enumerate_all_themes
      puts
      puts "#{info('[+]')} Enumerating installed themes #{'(only vulnerable ones)' if vane_options.enumerate_only_vulnerable_themes} ..."
      puts

      wp_themes = WpThemes.aggressive_detection(wp_target,
        enum_options.merge(
          file: vane_options.enumerate_all_themes ? THEMES_FULL_FILE : THEMES_FILE,
          only_vulnerable: vane_options.enumerate_only_vulnerable_themes || false
        )
      )
      puts
      if !wp_themes.empty?
        puts "#{info('[+]')} We found #{wp_themes.size} themes:"

        wp_themes.output(vane_options.verbose)
      else
        puts "#{info('[+]')} No themes found"
      end
    end

    if vane_options.enumerate_timthumbs
      puts
      puts "#{info('[+]')} Enumerating timthumb files ..."
      puts

      wp_timthumbs = WpTimthumbs.aggressive_detection(wp_target,
        enum_options.merge(
          file: DATA_DIR + '/timthumbs.txt',
          theme_name: wp_theme ? wp_theme.name : nil
        )
      )
      puts
      if !wp_timthumbs.empty?
        puts "#{info('[+]')} We found #{wp_timthumbs.size} timthumb file/s:"

        wp_timthumbs.output(vane_options.verbose)
      else
        puts "#{info('[+]')} No timthumb files found"
      end
    end

    # If we haven't been supplied a username/usernames list, enumerate them...
    if !vane_options.username && !vane_options.usernames && vane_options.wordlist || vane_options.enumerate_usernames
      puts
      puts "#{info('[+]')} Enumerating usernames ..."

      if wp_target.has_plugin?('stop-user-enumeration')
        puts "#{warning('[!]')} Stop User Enumeration plugin detected, results might be empty. " \
             "However a bypass exists, see stop_user_enumeration_bypass.rb in #{File.expand_path(File.dirname(__FILE__))}"
      end

      wp_users = WpUsers.aggressive_detection(wp_target,
        enum_options.merge(
          range: vane_options.enumerate_usernames_range,
          show_progression: false
        )
      )

      if wp_users.empty?
        puts "#{info('[+]')} We did not enumerate any usernames"

        if vane_options.wordlist
          puts 'Try supplying your own username with the --username option'
          puts
          exit(1)
        end
      else
        puts "#{info('[+]')} Identified the following #{wp_users.size} user/s:"
        wp_users.output(margin_left: ' ' * 4)
        if wp_users[0].login == "admin"
           puts "#{warning('[!]')} Default first WordPress username 'admin' is still used"
        end
      end

    else
      wp_users = WpUsers.new

      if vane_options.usernames
        File.open(vane_options.usernames).each do |username|
          wp_users << WpUser.new(wp_target.uri, login: username.chomp)
        end
      else
        wp_users << WpUser.new(wp_target.uri, login: vane_options.username)
      end
    end

    # Start the brute forcer
    bruteforce = true
    if vane_options.wordlist
      if wp_target.has_login_protection?

        protection_plugin = wp_target.login_protection_plugin()

        puts
        puts "#{warning('[!]')} The plugin #{protection_plugin.name} has been detected. It might record the IP and timestamp of every failed login and/or prevent brute forcing altogether. Not a good idea for brute forcing!"
        puts '[?] Do you want to start the brute force anyway ? [Y]es [N]o, default: [N]'

        bruteforce = false if vane_options.batch || Readline.readline !~ /^y/i
      end

      if bruteforce
        puts "#{info('[+]')} Starting the password brute forcer"

        begin
          wp_users.brute_force(
            vane_options.wordlist,
            show_progression: true,
            verbose: vane_options.verbose
          )
        ensure
          puts
          wp_users.output(show_password: true, margin_left: ' ' * 2)
        end
      else
        puts "#{critical('[!]')} Brute forcing aborted"
      end
    end

    stop_time   = Time.now
    elapsed     = stop_time - start_time
    used_memory = get_memory_usage - start_memory

    puts
    puts info("[+] Finished: #{stop_time.asctime}")
    puts info("[+] Memory used: #{used_memory.bytes_to_human}")
    puts info("[+] Elapsed time: #{Time.at(elapsed).utc.strftime('%H:%M:%S')}")
    exit(0) # must exit!

  rescue SystemExit, Interrupt

  rescue => e
    puts
    puts critical(e.message)

    if vane_options && vane_options.verbose
      puts critical('Trace:')
      puts critical(e.backtrace.join("\n"))
    end
    exit(1)
  ensure
    # Ensure a clean abort of Hydra
    # See https://github.com/vaneteam/vane/issues/461#issuecomment-42735615
    Browser.instance.hydra.abort
    Browser.instance.hydra.run
  end
end

main()
